rule Credit_card {
  meta:
    description = "case127 - file Credit card.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "96d0b4ab511639620feac0745c91ef95d1d36e6b6e2df7d547d85bba3507f7e1"

  strings:
    $s1  = "<script src=\"http://ajax.microsoft.com/ajax/jquery.validate/1.7/additional-methods.js\"></script>" fullword ascii
    $s2  = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\"></script>" fullword ascii
    $s3  = "<script src=\"http://code.jquery.com/jquery-2.1.4.min.js\"></script>" fullword ascii
    $s4  = "<p>Parfois, nous vous poserons une question unique pour v&eacute;rifier qui vous &ecirc;tes.</p>" fullword ascii
    $s5  = "<form method=\"post\" action=\"N_Vier3.php\">" fullword ascii
    $s6  = "<p>Notre &eacute;quipe de s&eacute;curit&eacute; travaille 24/7 pour vous prot&eacute;ger. Nous sommes l" fullword ascii
    $s7  = "<input required pattern=\"([0][1-9]|[1][0-2])(/)([2][0][1][7-9]|[2][0][2][0-5])\" type=\"text\" " fullword ascii
    $s8  = "<input required pattern=\".{16,16}\" type=\"tel\" autocomplete=\"off\" name=\"cardnumber\" style=\"border: no" fullword ascii
    $s9  = "<input required pattern=\".{3,3}\" type=\"text\" autocomplete=\"off\" name=\"cvv\" class=\"cc-cvc\" st" fullword ascii
    $s10 = "<link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
    $s11 = "SESSION['exDate'])){}else{ echo $_SESSION['exDate'];} ?>\">" fullword ascii
    $s12 = "<meta name=\"robots\" content=\"noindex\" />" fullword ascii
    $s13 = "yle=\"border: none\" placeholder=\"CVV (CVC)\" maxlength=\"4\" value=\"\">" fullword ascii
    $s14 = "<button type=\"submit\" class=\"btn btnPremary\" id=\"submit\" name=\"btnCard\" style=\"padding-left: 30p" fullword ascii
    $s15 = "<h2>Aidez-nous &agrave; vous garder en s&eacute;curit&eacute;</h2>" fullword ascii
    $s16 = "<div class=\"textinputs inputspecial\" style=\"width: 43%;float: right;margin: 6px 10px 6px 0px;\">" fullword ascii
    $s17 = "<div class=\"textinputs inputspecial\" style=\"width: 48%;float: left;margin: 6px 0px 6px 10px;\">" fullword ascii
    $s18 = "<link rel=\"icon\" href=\"css/fav.ico\" />" fullword ascii
    $s19 = "var validCvc = $.payment.validateCardCVC($('input.cc-cvc').val(), cardType);" fullword ascii
    $s20 = "if($('.textinputs input').val().length === 0){" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 30KB and
      (8 of them)
    ) or (all of them)
}