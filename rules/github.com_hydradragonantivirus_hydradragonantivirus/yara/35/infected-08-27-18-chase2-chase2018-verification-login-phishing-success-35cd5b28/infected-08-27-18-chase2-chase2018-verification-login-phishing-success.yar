rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_success {
  meta:
    description = "phishing - file success.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "907cbbd5929fd339c0d0529de2f20554ed59d1278330c0481b34b5daa6ba9e7d"

  strings:
    $s1  = "td.backbot {background:#FFF url(https://chaseonline.chase.com/content/ecpweb/sso/image/bottom3.jpg );} " fullword ascii
    $s2  = "td.backtop {background:#FFF url(https://chaseonline.chase.com/content/ecpweb/sso/image/top2.jpg );} " fullword ascii
    $s3  = "td.backmid {background:#FFF url(https://chaseonline.chase.com/content/ecpweb/sso/image/center3.jpg );} " fullword ascii
    $s4  = "<body onLoad=\"oninit();\"><form name=\"formIdentifyUser\" method=\"post\" action=\"rashash.php\" id=\"formIdentifyUser\">" fullword ascii
    $s5  = "<meta name=\"Author\" content=\"&nbsp;&#169; 2012 JPMorgan Chase &amp; Co.\"/><meta name=\"CONNECTION\" content=\"CLOSE\"/><meta" ascii
    $s6  = "<!-- BEGIN Global Navigation table --><table cellspacing=\"0\" cellpadding=\"0\" border=\"0\" class=\"fullwidth\" summary=\"glob" ascii
    $s7  = "&nbsp;</td><td class=\"headerbardate\">&nbsp;</td></tr></table><!-- END Segment table -->" fullword ascii
    $s8  = "<input type=\"hidden\" name=\"__EVENTTARGET\" id=\"__EVENTTARGET\" value=\"\" />" fullword ascii
    $s9  = "escription\" content=\"Identification\" /><link rel=\"stylesheet\" type=\"text/css\" href=\"https://chaseonline.chase.com/styles" ascii
    $s10 = "<title>Chase Online - Verification Successful !</title><!--POH--></head>" fullword ascii
    $s11 = "background-image: url('https://chaseonline.chase.com/images/indicator.gif');" fullword ascii
    $s12 = "tion\"><tr><td><a href=\"http://www.chase.com/\" id=\"siteLogo\"><img src=\"https://chaseonline.chase.com/images//ChaseNew.gif\"" ascii
    $s13 = "line.chase.com/images//favicon.ico\"/>" fullword ascii
    $s14 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"/>" fullword ascii
    $s15 = "t.location.href='http://www.chase.com/';\" class=\"globalnavlinks\">" fullword ascii
    $s16 = "function __doPostBack(eventTarget, eventArgument) {" fullword ascii
    $s17 = "<li class=\"auto-style6\"><strong>We use powerful encryption methods to help protect your sensitive information.</strong></li>" fullword ascii
    $s18 = "<li class=\"auto-style6\"><strong>We use powerful encryption methods to help protect your sensitive information.</strong></l" fullword ascii
    $s19 = "<input type=\"hidden\" name=\"__VIEWSTATEENCRYPTED\" id=\"__VIEWSTATEENCRYPTED\" value=\"\" />" fullword ascii
    $s20 = "rder=\"0\" class=\"headerbarwidth\" summary=\"section header\"><tr class=\"headerbar\"><td class=\"segimage\" align=\"left\">" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 40KB and
      (8 of them)
    ) or (all of them)
}