rule infected_08_17_18_linkedin_phishing_connect {
  meta:
    description = "phishing - file connect.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-17"
    hash1       = "42488aee3cec937049e5313438a033fd89993bba7627d55a40abdeed289e8ba6"

  strings:
    $s1  = "$country = file_get_contents('http://api.hostip.info/country.php?ip='.$IP);" fullword ascii
    $s2  = "header(\"Location: http://www.linkedin.com/pub/dir/Import/Export\");" fullword ascii
    $s3  = "$message .= \"-------------- LoginZ By By CYCLOPZ-----------------------\\n\";" fullword ascii
    $s4  = "$message .= \"Verify-Password: \".$_POST['paasv'].\"\\n\";" fullword ascii
    $s5  = "$message .= \"Password: \".$_POST['pass'].\"\\n\";" fullword ascii
    $s6  = "$headers = \"From:MESSAGE Mp Boss<CYCLOPZ@CYCLOPZ.COM>\";" fullword ascii
    $s7  = "$message .= \"Linkedin !ID: \".$_POST['session_key'].\"\\n\";" fullword ascii
    $s8  = "$log_date = date('d/m/Y - h:i:s');" fullword ascii
        $s10 = "mail(\"$to\", \"Linkedin Login\", $message);" fullword ascii
    $s11 = "$subject = \"Linkedin LOGIN\";" fullword ascii
    $s12 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
    $s13 = "if (mail($recipient,$subject,$message,$headers))" fullword ascii
    $s14 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s15 = "$message .= \"---------------Created By By bobychenko------------------------------\\n\";" fullword ascii
    $s16 = "$message .= \"Date : \".$log_date.\"\\n\";" fullword ascii
    $s17 = "$headers .= $_POST['name'].\"\\n\";" fullword ascii
    $s18 = "echo \"ERROR! Please go back and try again.\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 3KB and
      (8 of them)
    ) or (all of them)
}