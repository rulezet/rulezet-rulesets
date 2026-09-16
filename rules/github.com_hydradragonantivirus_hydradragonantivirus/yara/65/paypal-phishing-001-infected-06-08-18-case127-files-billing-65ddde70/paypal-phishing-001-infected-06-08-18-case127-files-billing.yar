rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_Billing {
  meta:
    description = "case127 - file Billing.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "5eda8b34d08c8a2b313072130adf38a7ab15b1507615406608274cf8d5ee32e5"

  strings:
    $s1  = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\"></script>" fullword ascii
    $s2  = "<script src=\"http://code.jquery.com/jquery-2.1.4.min.js\"></script>" fullword ascii
    $s3  = "<input type=\"text\" required name=\"zip\" placeholder=\"Code postal\"  style=\"width: 49%; float: left;\">" fullword ascii
    $s4  = "<p>Parfois, nous vous poserons une question unique pour v&eacute;rifier qui vous &ecirc;tes.</p>" fullword ascii
    $s5  = "<input  type=\"number\" required name=\"fnumber\" id=\"phone\"  placeholder=\"Mobile\" style=\"width: 49%; float" fullword ascii
    $s6  = "<h4>Nous allons maintenant v&eacute;rifier les informations de votre compte PayPal.</h4>" fullword ascii
    $s7  = "<input pattern=\"^([0][1-9]|[12][0-9]|3[01])(/)([0][1-9]|[1][0-2])\\2(\\d{4})$\" type=\"text\" name=\"dob\" " fullword ascii
    $s8  = "<input type=\"text\" name=\"fname\" required placeholder=\"Pr&eacute;nom\" style=\"width: 49%; float: left;\">" fullword ascii
    $s9  = "<input type=\"text\" name=\"fname\" required placeholder=\"Pr&eacute;nom\" style=\"width: 49%; float: left;" fullword ascii
    $s10 = "<input type=\"text\" name=\"lname\" required placeholder=\"Nom\"  style=\"width: 49%; float: right;\"></div>" fullword ascii
    $s11 = "<form method=\"post\" action=\"N_Vier2.php\">" fullword ascii
    $s12 = "<p>Notre &eacute;quipe de s&eacute;curit&eacute; travaille 24/7 pour vous prot&eacute;ger. Nous sommes l" fullword ascii
    $s13 = "<link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
    $s14 = "<meta name=\"robots\" content=\"noindex\" />" fullword ascii
    $s15 = "<h2>Aidez-nous &agrave; vous garder en s&eacute;curit&eacute;</h2>" fullword ascii
    $s16 = "<link rel=\"icon\" href=\"css/fav.ico\" />" fullword ascii
    $s17 = "<script src=\"../js/jquery.maskedinput.min.js\"></script>" fullword ascii
    $s18 = "<script>print_country(\"country\");</script>" fullword ascii
    $s19 = "<button type=\"submit\" class=\"btn btnPremary\" style=\"padding-left: 30px;padding-right: 40px;\" nam" fullword ascii
    $s20 = "if( $(this).val().length === 0 ) {" fullword ascii

  condition:
    (uint16(0) == 0x213c and
      filesize < 10KB and
      (8 of them)
    ) or (all of them)
}