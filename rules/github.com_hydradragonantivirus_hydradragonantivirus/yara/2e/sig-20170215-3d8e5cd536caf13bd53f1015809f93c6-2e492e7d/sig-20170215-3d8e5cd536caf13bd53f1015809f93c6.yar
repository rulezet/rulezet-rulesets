rule sig_20170215_3d8e5cd536caf13bd53f1015809f93c6 {
  meta:
    description = "datamaliciousorder - file 20170215_3d8e5cd536caf13bd53f1015809f93c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "758bd5f7efad43ffae68d36c744b1940b0588629b8e5feb95fb2c8899e2c4d81"

  strings:
    $x1  = "<!-- HTML Encryption provided by iWEBTOOL.com -->" fullword ascii
    $s2  = "<SCRIPT src=\"https://www.paypal.com/js/pp_main.js\"></SCRIPT>  " fullword ascii
    $s3  = "                                        document.write(<a href=\\javascript:openWindow640('https://www.paypal.com/cgi-bin/webscr" ascii
    $s4  = "<link rel=\"shortcut icon\" href=\"https://www.aexp-static.com/nav/ngn/img/logo_bluebox.gif\">  " fullword ascii
    $s5  = "    <TD><!-- Start of Text Counter --><!--    Description:  This will display a text counter on your webpage.  " fullword ascii
    $s6  = "                                        document.write(<a href=\\javascript:openWindow640('https://www.paypal.com/cgi-bin/webscr" ascii
    $s7  = "<!-- End of Text Counter -->&nbsp;</TD></TR></TBODY></TABLE></BODY></HTML>  " fullword ascii
    $s8  = "            target=_new>User Agreement</A></NOSCRIPT></SPAN><SPAN  " fullword ascii
    $s9  = "<LINK href=\"https://www.paypalobjects.com/css/pp_styles_082102.css\"  " fullword ascii
    $s10 = "<HTML><HEAD><TITLE>American Express - Online Services | |Card Membership Verification</TITLE>  " fullword ascii
    $s11 = "      about FDIC pass-through insurance</A></TD></TR></TBODY></TABLE><!-- end footer --></FORM>  " fullword ascii
    $s12 = "            target=_new>Privacy Policy.</A></NOSCRIPT>  " fullword ascii
    $s13 = "            for=login_password>Password: </TD>  " fullword ascii
    $s14 = "                <TD class=ppsmalltext><B>Email Address & Password</B> - Enter your information as it appears on your Email Accou" ascii
    $s15 = "      href=\"https://www.paypal.com/us/cgi-bin/webscr?cmd=xpt/Marketing/popup/WaxAboutPaypal-outside&amp;justSecure=true\">Secur" ascii
    $s16 = "                <TD class=ppsmalltext><B>Email Address & Password</B> - Enter your information as it appears on your Email Accou" ascii
    $s17 = "                <TD class=ppsmalltext><B>User ID & Password</B> - Enter your Login details as it appears on your American Expres" ascii
    $s18 = "                <TD class=ppsmalltext><B>User ID & Password</B> - Enter your Login details as it appears on your American Expres" ascii
    $s19 = "      href=\"https://www.paypal.com/us/cgi-bin/webscr?cmd=xpt/Marketing/popup/WaxAboutPaypal-outside&amp;justSecure=true\">Secur" ascii
    $s20 = "            for=login_password>Email Password: </TD>  " fullword ascii

  condition:
    uint16(0) == 0x483c and
    1 of ($x*) and 4 of them
}