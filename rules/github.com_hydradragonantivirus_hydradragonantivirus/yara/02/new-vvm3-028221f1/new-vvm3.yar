rule new_vvm3 {
  meta:
    description = "Navy - file new_vvm3.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2020-07-23"
    hash1       = "bee462cb420ca448709a68defec6d2e200d717019dfe9315bd8f06ed5f7c756a"

  strings:
    $s1  = "if (!socket_connect($socket, $hp[0], $hp[1])){socket_close($socket);}else{socket_write($socket, \"GET http://\".$sd.\"/post.php " ascii
    $s2  = "socket_write($socket, \"GET http://\".$sd.\"/cpost.php HTTP/1.1\\r\\nHost: \".$host[0].\"\\r\\nCookie: \".$data.\"\\r\\n\\r\\n\"" ascii
    $s3  = "socket_write($socket, \"GET http://\".$sd.\"/cpost.php HTTP/1.1\\r\\nHost: \".$host[0].\"\\r\\nCookie: \".$data.\"\\r\\n\\r\\n\"" ascii
    $s4  = "if(empty($hostname)) return;$exec='nslookup -type=MX '.escapeshellarg($hostname);@exec($exec,$output);if(empty($output)) return;" ascii
    $s5  = "if(empty($hostname)) return;$exec='nslookup -type=MX '.escapeshellarg($hostname);@exec($exec,$output);if(empty($output)) return;" ascii
    $s6  = "fputs($fp,base64_encode($mail.\" \".hash_hmac('MD5', base64_decode(substr($authchal, 4)) ,$pass)).\"\\r\\n\");$code = substr(get" ascii
    $s7  = "post_mch($sd,'OK',$rel.';||'.$host.'||'.$port.'||'.$mail.'||'.$pass);" fullword ascii
    $s8  = "if (!$afp) {post_stats('A1');exit;}fwrite($afp, \"GET \".$atte[0].\" HTTP/1.0\\r\\nHost: \".$affdom[0].\"\\r\\nConnection: Close" ascii
    $s9  = "if (!$afp) {post_stats('A1');exit;}fwrite($afp, \"GET \".$atte[0].\" HTTP/1.0\\r\\nHost: \".$affdom[0].\"\\r\\nConnection: Close" ascii
    $s10 = "fputs($fp,\"AUTH LOGIN\\r\\n\");$code = substr(get_data($fp),0,3);if($code != 334) {fclose($fp); return (\"BAUTH\");}" fullword ascii
    $s11 = "fputs($fp,\"AUTH LOGIN\\r\\n\");$code = substr(get_data($fp),0,3);" fullword ascii
    $s12 = "function smtp_lookup($host){if(function_exists(\"getmxrr\")){getmxrr($host,$mxhosts,$mxweight);return $mxhosts[0];}else{win_getm" ascii
    $s13 = "function smtp_lookup($host){if(function_exists(\"getmxrr\")){getmxrr($host,$mxhosts,$mxweight);return $mxhosts[0];}else{win_getm" ascii
    $s14 = "function mch($host,$port,$mail,$pass){" fullword ascii
    $s15 = "if (!socket_connect($socket, $hp[0], $hp[1])){socket_close($socket);}else{socket_write($socket, \"GET http://\".$sd.\"/post.php " ascii
    $s16 = "}else if(strripos($authcheck, 'LOGIN')){" fullword ascii
    $s17 = "$len_login = chr(strlen($sl));" fullword ascii
    $s18 = "$h=pack(\"H*\",\"01\").$len_login.$sl.$len_pass.$sc;" fullword ascii
    $s19 = "$hostname = gethostbyaddr($unkhost);" fullword ascii
    $s20 = "$duri='smtp/'.$host.'/'.$pd;" fullword ascii

  condition:
    uint16(0) == 0x3f3c and filesize < 60KB and
    8 of them
}