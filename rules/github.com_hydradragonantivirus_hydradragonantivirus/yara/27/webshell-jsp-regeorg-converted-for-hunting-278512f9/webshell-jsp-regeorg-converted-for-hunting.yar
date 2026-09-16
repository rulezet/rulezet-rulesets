rule webshell_jsp_regeorg__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "Webshell regeorg JSP version"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "https://github.com/sensepost/reGeorg"
    key   = "Arnim Rupp"
    key   = "2021/01/24"
    score = 40

  strings:
    $jgeorg1     = "request" fullword wide ascii
    $jgeorg2     = "getHeader" fullword wide ascii
    $jgeorg3     = "X-CMD" fullword wide ascii
    $jgeorg4     = "X-STATUS" fullword wide ascii
    $jgeorg5     = "socket" fullword wide ascii
    $jgeorg6     = "FORWARD" fullword wide ascii
    $cjsp_short1 = "<%" ascii wide
    $cjsp_short2 = "%>" wide ascii
    $cjsp_long1  = "<jsp:" ascii wide
    $cjsp_long2  = /language=[\"']java[\"\']/ ascii wide
    $cjsp_long3  = "/jstl/core" ascii wide
    $cjsp_long4  = "<%@p" nocase ascii wide
    $cjsp_long5  = "<%@ " nocase ascii wide
    $cjsp_long6  = "<% " ascii wide
    $cjsp_long7  = "< %" ascii wide

  condition:
    (filesize >= 300KB and filesize < 900KB
    )
    and
    ($cjsp_short1 at 0 or any of ($cjsp_long*) or $cjsp_short2 in (filesize - 100..filesize) or
      ($cjsp_short2 and
        ($cjsp_short1 in (0..1000) or $cjsp_short1 in (filesize - 1000..filesize)))) and all of ($jgeorg*)
}