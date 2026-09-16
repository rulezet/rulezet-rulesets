rule infected_phishing_functions {
  meta:
    description = "phishing - file functions.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "ac14e54b724e7990ea298f51472ec7c41b721740d19ac2a53706b3050893d386"

  strings:
    $x1  = "$ipDetails = json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\" . $ipAddress), true);" fullword ascii
    $s2  = "$bankDetails = json_decode(file_get_contents(\"http://www.binlist.net/json/\" . $cardBIN), true);" fullword ascii
    $s3  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.13+ (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2" fullword ascii
    $s4  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 1083) AppleWebKit/536.28.4 (KHTML like Gecko) Version/6.0.3 Safari/536.28.4" fullword ascii
    $s5  = "$systemInfo['useragent'] = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
    $s6  = "$uagent = strtolower($uagent ? $uagent : $_SERVER['HTTP_USER_AGENT']);" fullword ascii
    $s7  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 1082) AppleWebKit/537.11 (KHTML like Gecko) Chrome/23.0.1271.10 Safari/537.11" fullword ascii
    $s8  = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.57 Safari/537.17" fullword ascii
    $s9  = "if(preg_match('/MSIE/i',$u_agent) && !preg_match('/Opera/i',$u_agent))" fullword ascii
    $s10 = "elseif (preg_match('/macintosh|mac os x/i', $u_agent)) {" fullword ascii
    $s11 = "$systemInfo['os'] = os_info($systemInfo['useragent']);" fullword ascii
    $s12 = "// Next get the name of the useragent yes seperately and for good reason" fullword ascii
    $s13 = "$browserName = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
    $s14 = "Opera/12.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.02" fullword ascii
    $s15 = "Opera/9.80 (Windows NT 6.2; U; en) Presto/2.10.289 Version/12.01" fullword ascii
    $s16 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)" fullword ascii
    $s17 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)" fullword ascii
    $s18 = "$randomString .= $characters[rand(0, strlen($characters) - 1)];" fullword ascii
    $s19 = "$u_agent = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
    $s20 = "if (strripos($u_agent,\"Version\") < strripos($u_agent,$ub)){" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}