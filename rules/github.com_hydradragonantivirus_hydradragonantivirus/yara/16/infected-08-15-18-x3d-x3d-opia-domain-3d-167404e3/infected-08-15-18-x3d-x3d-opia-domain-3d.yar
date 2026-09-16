rule infected_08_15_18_X3D_X3D_OPIA_DOMAIN_3d {
  meta:
    description = "X3D-OPIA-DOMAIN - file 3d.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-15"
    hash1       = "02294ec86c939ba55355c0b2b85991f3b79d172d4d240ad3bbdf64d02bd1762e"

  strings:
            $s3  = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
            $s7  = "$ip = $client;" fullword ascii
    $s8  = "$ip = $forward;" fullword ascii
    $s9  = "loading.php?email=$login&.rand=" fullword ascii
    $s10 = "elseif(filter_var($forward" fullword ascii
                    
  condition:
    (uint16(0) == 0x3f3c and
      filesize < 10KB and
      (4 of them)
    ) or (all of them)
}