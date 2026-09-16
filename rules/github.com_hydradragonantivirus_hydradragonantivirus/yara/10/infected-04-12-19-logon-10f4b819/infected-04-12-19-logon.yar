rule infected_04_12_19_Logon {
  meta:
    description = "04-12-19 - file Logon.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-04-12"
    hash1       = "6f1757cb95bf4261459cf829a0cb32688a9c328951bd054611f28ca10916e93e"

  strings:
    $s1  = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
                                    $s10 = "$hostname = gethostbyaddr($ip);" fullword ascii
                    $s15 = "$passchk = strlen($password);" fullword ascii
            $s18 = "$ip = getenv(" fullword ascii
        $s20 = "elseif(filter_var($forward" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 7KB and
      (8 of them)
    ) or (all of them)
}