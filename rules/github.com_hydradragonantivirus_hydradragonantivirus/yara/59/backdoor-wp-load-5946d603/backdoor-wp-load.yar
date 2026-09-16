rule backdoor_wp_load {
  meta:
    description = "work1 - file backdoor_wp-load.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "527fdc5e4dc719fc97f61aa85b9edc33e90d9fd2ed3dbcda30ce25f4e1d5c908"

  strings:
    $s1  = "= str_replace('sx', '64', $ee); $algo = 'kolotyska'; $pass = \"Zgc5c4MXrL8kbQBSs88NKfKeflvUNPlfnyDNGK/X/wEfeQ==\";" fullword ascii
    $s2  = "if (fopen(\"$subdira/.$algo\", 'w')) { $ura = 1; $eb = \"$subdira/\"; $hdl = fopen(\"$subdira/.$algo\", 'w'); break; }" fullword ascii
    $s3  = "$data = file_get_contents($url);" fullword ascii
    $s4  = "if (fopen(\"$dira/.$algo\", 'w')) { $ura = 1; $eb = \"$dira/\"; $hdl = fopen(\"$dira/.$algo\", 'w'); break; }" fullword ascii
    $s5  = "if (!$ura && fopen(\".$algo\", 'w')) { $ura = 1; $eb = ''; $hdl = fopen(\".$algo\", 'w'); }" fullword ascii
    $s6  = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
    $s7  = "$reqw = $ay($ao($oa(\"$pass\"), 'wp_function'));" fullword ascii
    $s8  = "curl_setopt($ch, CURLOPT_HEADER, 0);" fullword ascii
    $s9  = "function get_data_ya($url) {" fullword ascii
    $s10 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
    $s11 = "@ini_set('display_errors', '0');" fullword ascii

  condition:
    (uint16(0) == 0x3c0a and
      filesize < 10KB and
      (8 of them)
    ) or (all of them)
}