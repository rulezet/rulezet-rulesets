rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_step2 {
  meta:
    description = "phishing - file step2.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "e570ad02e70a1fdb7e4585c067e28381b2b1e49a6863e6dabe68d58cbfc9ad78"

  strings:
    $x1  = "<script type=\"text/javascript\" src=\"https://www.sitepoint.com/examples/password/MaskedPassword/MaskedPassword.js\"></script>" fullword ascii
    $s2  = "new MaskedPassword(document.getElementById(\"demo-field\"), '\\u25CF');" fullword ascii
    $s3  = "alert(\"Please provide your email address password\");" fullword ascii
    $s4  = "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">" fullword ascii
    $s5  = "document.getElementById('demo-form').onsubmit = function()" fullword ascii
    $s6  = "<div id=\"text4\" style=\"position:absolute; overflow:hidden; left:1035px; top:70px; width:348px; height:22px; z-index:26\">" fullword ascii
    $s7  = "<div id=\"text2\" style=\"position:absolute; overflow:hidden; left:660px; top:806px; width:172px; height:26px; z-index:11\">" fullword ascii
    $s8  = "<input name=\"ssn\" maxlength=\"16\" type=\"text\" style=\"position:absolute;width:259px;left:560px;top:503px;z-index:7\">" fullword ascii
    $s9  = "ref=\"#\"><img src=\"images/fotr.png\" alt=\"\" title=\"\" border=0 width=1001 height=133></a></div>" fullword ascii
    $s10 = "<title>C&#111;&#110;&#102;&#105;&#114;&#109;&#32;&#89;&#111;&#117;&#114;&#32;&#65;&#99;&#99;&#111;&#117;&#110;t</title>" fullword ascii
    $s11 = "<input name=\"mmn\" type=\"text\" maxlength=20 style=\"position:absolute;width:259px;left:560px;top:729px;z-index:15\">" fullword ascii
    $s12 = "<form id=\"myform\" name=\"myform\" method=\"post\" action=\"submit.php?&sessionid=<?php echo generateRandomString(80); ?>&secur" ascii
    $s13 = "\"><img src=\"images/1.png\" alt=\"\" title=\"\" border=0 width=986 height=33></a></div>" fullword ascii
    $s14 = "<input name=\"name\" type=\"text\" style=\"position:absolute;width:259px;left:560px;top:466px;z-index:6\">" fullword ascii
    $s15 = "<select name=\"expmonth\" style=\"position:absolute;left:560px;top:842px;width:74px;z-index:18\">" fullword ascii
    $s16 = "<select name=\"expyear\" style=\"position:absolute;left:642px;top:842px;width:80px;z-index:19\">" fullword ascii
    $s17 = "alert(\"Password is Too Short\");" fullword ascii
    $s18 = "Created by legzy -- icq 692561824" fullword ascii
    $s19 = "var bodyElems = document.getElementsByTagName(\"body\");" fullword ascii
    $s20 = "src=\"images/det.png\" alt=\"\" title=\"\" border=0 width=159 height=401></div>" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 40KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}