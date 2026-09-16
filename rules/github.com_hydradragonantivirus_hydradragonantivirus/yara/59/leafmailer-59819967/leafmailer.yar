rule leafmailer {
  meta:
    description = "Tryag-File-Manager-jpeg-master - file leafmailer.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-14"
    hash1       = "26b6e96b0103e547b08cabb2b0ef1f14acab5b154ffc69a1afc85c8dc47ae029"

  strings:
    $x1  = "print \"<pre align=center><form method=post>Password: <input type='password' name='pass'><input type='submit' value='>>'>" fullword ascii
    $s2  = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\"></script>" fullword ascii
    $s3  = "<link href=\"https://maxcdn.bootstrapcdn.com/bootswatch/3.3.6/cosmo/bootstrap.min.css\" rel=\"stylesheet\" >" fullword ascii
    $s4  = "* Options are LOGIN (default), PLAIN, NTLM, CRAM-MD5" fullword ascii
    $s5  = "$sendmail = sprintf('%s -oi -f%s -t', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));" fullword ascii
    $s6  = "$sendmail = sprintf('%s -f%s', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));" fullword ascii
    $s7  = "$privKeyStr = file_get_contents($this->DKIM_private);" fullword ascii
    $s8  = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
    $s9  = "<li>hello <b>[-emailuser-]</b> -> hello <b>user</b></li>" fullword ascii
    $s10 = "$sendmail = sprintf('%s -oi -t', escapeshellcmd($this->Sendmail));" fullword ascii
    $s11 = "Reciver Email = <b>user@domain.com</b><br>" fullword ascii
    $s12 = "$DKIMb64 = base64_encode(pack('H*', sha1($body))); // Base64 of packed binary SHA-1 hash of body" fullword ascii
    $s13 = "* and creates a plain-text version by converting the HTML." fullword ascii
    $s14 = "* Usually the email address used as the source of the email" fullword ascii
    $s15 = "<li>your code is  <b>[-randommd5-]</b> -> your code is <b>e10adc3949ba59abbe56e057f20f883e</b></li>" fullword ascii
    $s16 = "print \"<pre align=center><form method=post>Password: <input type='password' name='pass'><input type='submit' value='>>'></form>" ascii
    $s17 = "* PHPMailer only supports some preset message types," fullword ascii
    $s18 = "* @param string $patternselect A selector for the validation pattern to use :" fullword ascii
    $s19 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>" fullword ascii
    $s20 = "if (isset($_REQUEST['pass']) and $_REQUEST['pass'] == $password) {" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 400KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}