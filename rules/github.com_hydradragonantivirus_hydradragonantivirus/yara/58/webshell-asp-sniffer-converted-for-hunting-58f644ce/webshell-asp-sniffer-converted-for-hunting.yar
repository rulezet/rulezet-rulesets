rule webshell_asp_sniffer__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "ASP webshell which can sniff local traffic"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/03/14"
    score = 40

  strings:
    $sniff1          = "Socket(" wide ascii
    $sniff2          = ".Bind(" wide ascii
    $sniff3          = ".SetSocketOption(" wide ascii
    $sniff4          = ".IOControl(" wide ascii
    $sniff5          = "PacketCaptureWriter" fullword wide ascii
    $tagasp_short1   = /<%[^"]/ wide ascii
    $tagasp_short2   = "%>" wide ascii
    $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
    $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
    $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
    $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
    $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
    $tagasp_long10   = "<%@ " wide ascii
    $tagasp_long11   = /<% \w/ nocase wide ascii
    $tagasp_long12   = "<%ex" nocase wide ascii
    $tagasp_long13   = "<%ev" nocase wide ascii
    $tagasp_long20   = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
    $tagasp_long32   = /<script\s{1,30}runat=/ wide ascii
    $tagasp_long33   = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
    $php1            = "<?php"
    $php2            = "<?="
    $jsp1            = "=\"java." wide ascii
    $jsp2            = "=\"javax." wide ascii
    $jsp3            = "java.lang." wide ascii
    $jsp4            = "public" fullword wide ascii
    $jsp5            = "throws" fullword wide ascii
    $jsp6            = "getValue" fullword wide ascii
    $jsp7            = "getBytes" fullword wide ascii
    $perl1           = "PerlScript" fullword
    $asp_input1      = "request" fullword nocase wide ascii
    $asp_input2      = "Page_Load" fullword nocase wide ascii
    $asp_input3      = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
    $asp_xml_http    = "Microsoft.XMLHTTP" fullword nocase wide ascii
    $asp_xml_method1 = "GET" fullword wide ascii
    $asp_xml_method2 = "POST" fullword wide ascii
    $asp_xml_method3 = "HEAD" fullword wide ascii
    $asp_form1       = "<form " wide ascii
    $asp_form2       = "<Form " wide ascii
    $asp_form3       = "<FORM " wide ascii
    $asp_asp         = "<asp:" wide ascii
    $asp_text1       = ".text" wide ascii
    $asp_text2       = ".Text" wide ascii

  condition:
    ((any of ($tagasp_long*) or any of ($tagasp_classid*) or
        ($tagasp_short1 and $tagasp_short2 in (filesize - 100..filesize)) or
        ($tagasp_short2 and
          ($tagasp_short1 in (0..1000) or $tagasp_short1 in (filesize - 1000..filesize)))) and not ((any of ($perl*) or $php1 at 0 or $php2 at 0) or
        ((#jsp1 + #jsp2 + #jsp3) > 0 and
          (#jsp4 + #jsp5 + #jsp6 + #jsp7) > 0))) and
    (any of ($asp_input*) or
      ($asp_xml_http and any of ($asp_xml_method*)) or
      (any of ($asp_form*) and any of ($asp_text*) and $asp_asp)) and (filesize >= 30KB and filesize < 90KB
    )
    and all of ($sniff*)
}