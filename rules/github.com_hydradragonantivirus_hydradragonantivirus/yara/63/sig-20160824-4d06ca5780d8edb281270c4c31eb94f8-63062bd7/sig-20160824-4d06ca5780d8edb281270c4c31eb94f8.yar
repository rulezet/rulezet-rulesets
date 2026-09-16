rule sig_20160824_4d06ca5780d8edb281270c4c31eb94f8 {
  meta:
    description = "datamaliciousorder - file 20160824_4d06ca5780d8edb281270c4c31eb94f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6301636e18bae68be94b509740f17252bcbf89a60340cad2b09606899ce5e80"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}