rule backdoor_countyu {
  meta:
    description = "work1 - file backdoor_countyu.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "a539719a580d96a952b5e81928b0c50d5fac7c35f84ca83a143c929f67c1806b"

  strings:
    $s1  = "$mb4a88417b3d0170d = file_get_contents(base64_decode($v634894f9845d8dc65).$kkk557);" fullword ascii
    $s2  = "curl_setopt($kd88fc6edf21ea464, CURLOPT_USERAGENT, base64_decode('bmV3cmVxdWVzdA=='));" fullword ascii
    $s3  = "$ke4e46deb7f9cc58c = json_decode(base64_decode(fread($se1260894f59eeae9, filesize($s8c7dd922ad47494f))) , 1);" fullword ascii
    $s4  = "$ye617ef6974faced4 = base64_decode('aHR0cDovLw==') . $ke4e46deb7f9cc58c[base64_decode('ZG9tYWlu') ] . $ed6fe1d0be6347b8e;" fullword ascii
    $s5  = "$ye617ef6974faced4 = base64_decode('aHR0cDovLw==') . $m9b207167e5381c47[base64_decode('ZG9tYWlu') ] . $ed6fe1d0be6347b8e;" fullword ascii
    $s6  = "unlink($s8c7dd922ad47494f); $ab4a88417b3d0170f = base64_decode('TG9jYXRpb246IA==') . $ye617ef6974faced4;" fullword ascii
    $s7  = "$d07cc694b9b3fc636 = $h77e8e1445762ae1a - $deaa082fa57816233;" fullword ascii
    $s8  = "$mb4a88417b3d0170d = curl_exec($kd88fc6edf21ea464);" fullword ascii
    $s9  = "curl_setopt($kd88fc6edf21ea464, CURLOPT_URL, base64_decode($v634894f9845d8dc65).$kkk557);" fullword ascii
    $s10 = "$v634894f9845d8dc65 = 'aHR0cDovL3JvaS10cmFmZmljLmljdS9nZXQucGhwP2Y9anNvbiZrZXk9';" fullword ascii
    $s11 = "$h0666f0acdeed38d4 = @fopen($s8c7dd922ad47494f, base64_decode('dys='));" fullword ascii
    $s12 = "$se1260894f59eeae9 = @fopen($s8c7dd922ad47494f, base64_decode('cg=='));" fullword ascii
    $s13 = "$ke4e46deb7f9cc58c = json_decode($mb4a88417b3d0170d, true);" fullword ascii
    $s14 = "$s8c7dd922ad47494f = dirname(__FILE__) . \"/\" . md5($ed6fe1d0be6347b8e);" fullword ascii
    $s15 = "if ($m9b207167e5381c47[base64_decode('ZG9tYWlu') ]) {" fullword ascii
    $s16 = "if ($ke4e46deb7f9cc58c[base64_decode('ZG9tYWlu') ]) {" fullword ascii
    $s17 = "$bb4a88417b3d0170f = strlen($ab4a88417b3d0170f); header(\"Set-Cookie: bb4a88417b3d0170f=$bb4a88417b3d0170f\"); header($ab4a88417" ascii
    $s18 = "$bb4a88417b3d0170f = strlen($ab4a88417b3d0170f); header(\"Set-Cookie: bb4a88417b3d0170f=$bb4a88417b3d0170f\"); header($ab4a88417" ascii
    $s19 = "$m9b207167e5381c47 = v64547f9857d8dc65($s8c7dd922ad47494f);" fullword ascii
    $s20 = "$kkk557 = \"723d60518a520564b23f4de72fd97781\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 7KB and
      (8 of them)
    ) or (all of them)
}