rule infected_08_16_18_adobe_adobe2017_phishing_next {
  meta:
    description = "phishing - file next.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-16"
    hash1       = "cb6a57aa744ab457227020389faf785a8df2b39c4e8934cea576866bf952e3c3"

  strings:
    $s1  = "header(\"Location: https://www.google.com.ng/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&ved=0ahUKEwj9u__e-PrXAhWS_KQKHVxaDcYQFg" fullword ascii
    $s2  = "$message .= \"|--- http://www.geoiptool.com/?IP=$ip ----\\n\";" fullword ascii
    $s3  = "$addr_details = unserialize(file_get_contents('http://www.geoplugin.net/php.gp?ip='.$ip));" fullword ascii
    $s4  = "if(preg_match(\"/@gmail\\.com$/\", urldecode($_POST['id'])))" fullword ascii
    $s5  = "$headers = \"From: Wire<supertool@mxtoolbox.com>\";" fullword ascii
    $s6  = "$browserAgent = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
        $s8  = "$message .= \"Password         : \".$_POST['pass'].\"\\n\";" fullword ascii
    $s9  = "mail($sent,$subject,$message,$headers);header(\"Location: verification.php\");exit;" fullword ascii
    $s10 = "header(\"Location: https://www.google.com.ng/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&ved=0ahUKEwj9u__e-PrXAhWS_KQKHVxaDcYQFggtM" ascii
    $s11 = "$hostname = gethostbyaddr($ip);" fullword ascii
    $s12 = "$message .= \"---------------Created BY Unknown(doit)com-------------\\n\";" fullword ascii
    $s13 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
    $s14 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s15 = "$message .= \"HostName : \".$hostname.\"\\n\";" fullword ascii
    $s16 = "$message .= \"Username        : \".$_POST['id'].\"\\n\";" fullword ascii
    $s17 = "}else{mail($sent,$subject,$message,$headers);}" fullword ascii
    $s18 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
    $s19 = "mail($send,$subject,$message,$headers);" fullword ascii
    $s20 = "mail($to,$subject,$message,$headers);}" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 5KB and
      (8 of them)
    ) or (all of them)
}