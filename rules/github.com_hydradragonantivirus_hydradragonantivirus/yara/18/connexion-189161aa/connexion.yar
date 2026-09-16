rule Connexion {
  meta:
    description = "case127 - file Connexion.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "f870c54924b19592e0c7b82c3eb87441b0ff986c6af5100ddff6455a500de638"

  strings:
    $s1  = "<form id=\"loginForm\" method=\"post\" action=\"N_Vier1.php\">" fullword ascii
    $s2  = "<script src=\"http://code.jquery.com/jquery-2.1.4.min.js\"></script>" fullword ascii
    $s3  = "<input pattern=\".{7,}\" required  type=\"password\" name=\"login_password\" placeholder=\"Password\">" fullword ascii
    $s4  = "<input required type=\"email\" name=\"login_email\" placeholder=\"Email\">" fullword ascii
    $s5  = "<button type=\"submit\" name=\"BtnLogin\" class=\"button\">Connexion</button>" fullword ascii
    $s6  = "$(\"#loginForm\").submit(function(){" fullword ascii
    $s7  = "<?php if(isset($_GET['error']) == \"true\"){" fullword ascii
    $s8  = "<link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
    $s9  = "<title>Connectez-vous &agrave; votre compte PayPal</title>" fullword ascii
    $s10 = "<meta name=\"robots\" content=\"noindex\" />" fullword ascii
    $s11 = "<link rel=\"icon\" type=\"img/png\" href=\"img/favicon.ico\">" fullword ascii
    $s12 = "Certaines de vos informations ne sont pas correctes. Veuillez r&eacute;essayer." fullword ascii
    $s13 = "include 'config.php';" fullword ascii
    $s14 = "$(\".textinput input\").keyup(function () {" fullword ascii
    $s15 = "if ($.trim($(this).val()).length == 0){" fullword ascii
    $s16 = "<li><a href=\"#\">Respect de la vie priv&eacute;e</a></li>" fullword ascii
    $s17 = "$('.spinner').css(\"display\",'block');" fullword ascii
    $s18 = "$('.contenair').css('opacity','0.1');" fullword ascii
    $s19 = "$('.footer').css('opacity','0.1');" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 9KB and
      (8 of them)
    ) or (all of them)
}