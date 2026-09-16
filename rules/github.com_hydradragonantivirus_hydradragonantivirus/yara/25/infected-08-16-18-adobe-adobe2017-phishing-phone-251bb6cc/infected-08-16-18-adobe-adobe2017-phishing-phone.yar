rule infected_08_16_18_adobe_adobe2017_phishing_phone {
  meta:
    description = "phishing - file phone.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-16"
    hash1       = "91061918168cd0532dcec6ec7493b6f18df78ce95d549cc6ed27475dab43c618"

  strings:
    $s1  = "header(\"Location: http://www.dfs.ny.gov/insurance/life/insurers/forms/LSP-Escrow.doc\");" fullword ascii
    $s2  = "$headers = \"From: PHONE ETC<customer-support@Spammers>\";" fullword ascii
    $s3  = "} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) { " fullword ascii
    $s4  = "$ip = $_SERVER['HTTP_X_FORWARDED_FOR']; " fullword ascii
    $s5  = "$send = \"sikkens40@zoho.com\";" fullword ascii
    $s6  = "$subject = \"Esrow - \".$country;" fullword ascii
    $s7  = "if($_POST[\"verify\"] != \"\" and $_POST[\"verify\"] != \"\"){" fullword ascii
    $s8  = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
    $s9  = "$message .= \"recovery: \".$_POST['verify'].\"\\n\";" fullword ascii
    $s10 = "$message .= \"---------=IP Address & Date=--------\\n\";" fullword ascii
    $s11 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
    $s12 = "mail($send,$subject,$message,$headers);" fullword ascii
    $s13 = "mail($to,$subject,$message,$headers);" fullword ascii
    $s14 = "if (!empty($_SERVER['HTTP_CLIENT_IP'])) { " fullword ascii
    $s15 = "$message .= \"IP Address: \".$ip.\"\\n\";" fullword ascii
    $s16 = "$message .= \"--------------PHONE ETC-----------------------\\n\";" fullword ascii
    $s17 = "$ip = $_SERVER['HTTP_CLIENT_IP']; " fullword ascii
    $s18 = "\"Country Code: {$geoplugin->countryCode}\\n\";" fullword ascii
    $s19 = "$message .= \"-------------------------------------\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 4KB and
      (8 of them)
    ) or (all of them)
}