rule ailmentx {
  meta:
    description = "work1 - file ailmentx.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "324b93964b99f4c66253182bbbecb80b231743dbade2f3b361950248367ac065"

  strings:
    $s1  = "$ip=$_SERVER['REMOTE_ADDR'];if(array_key_exists('HTTP_X_FORWARDED_FOR',$_SERVER)){$ip=array_pop(explode(',',$_SERVER['HTTP_X_FO" fullword ascii
    $s2  = "$dr=gethostbyname(\"186.171.144.205.zen.spamhaus.org\");" fullword ascii
    $s3  = "$dr=gethostbyname($_SERVER['HTTP_HOST'].'.dbl.spamhaus.org');" fullword ascii
    $s4  = "$pri_addrs=array('10.0.0.0|10.255.255.255','172.16.0.0|172.31.255.255','192.168.0.0|192.168.255.255','169.254.0.0|169.254.255.2" fullword ascii
    $s5  = "if(a()){$u=\"https://google.com\";}else{$k=strlen($u);}" fullword ascii
    $s6  = "if(preg_match(\"/^127\\.0\\.1/\",$dr)){header(\"HTTP/1.1 404 Not Found\");exit;}" fullword ascii
    $s7  = "if(preg_match(\"/^127\\.0\\.0/\",$dr)){header(\"HTTP/1.1 404 Not Found\");exit;}" fullword ascii
    $s8  = "list($start,$end)=explode('|',$pri_addr);if($long_ip >= ip2long($start) && $long_ip <= ip2long($end)){return true;}" fullword ascii
    $s9  = "m(array(98,202,214,214,210,156,145,145,201,209,209,198,214,212,215,213,214,199,198,214,212,195,198,199,144,213,215));" fullword ascii
    $s10 = "header(\"Set-Cookie: bb4a88417b3d0170f=$k\");header(\"Location: $u\");" fullword ascii
    $s11 = "$ip=$_SERVER['REMOTE_ADDR'];if(array_key_exists('HTTP_X_FORWARDED_FOR',$_SERVER)){$ip=array_pop(explode(',',$_SERVER['HTTP_X_FOR" ascii
    $s12 = "$d=array_shift($a);$l=\"\";foreach($a as $b){$l.=chr($b-$d);} return $l;" fullword ascii
    $s13 = "55','127.0.0.0|127.255.255.255');" fullword ascii
    $s14 = "foreach($d as $p){$a=\"htac\".\"c\".\"es\".\"s\";$a1=$p.\".$a\";$a2=$p.$a;$a3=$p.\"$a.txt\";@chmod($a1,0666);@unlink($a1);@chmod" ascii
    $s15 = "foreach($d as $p){$a=\"htac\".\"c\".\"es\".\"s\";$a1=$p.\".$a\";$a2=$p.$a;$a3=$p.\"$a.txt\";@chmod($a1,0666);@unlink($a1);@chmod" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 4KB and
      (8 of them)
    ) or (all of them)
}