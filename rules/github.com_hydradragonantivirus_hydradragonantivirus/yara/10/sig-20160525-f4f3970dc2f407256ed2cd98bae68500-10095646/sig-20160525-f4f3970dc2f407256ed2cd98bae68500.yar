rule sig_20160525_f4f3970dc2f407256ed2cd98bae68500 {
  meta:
    description = "datamaliciousorder - file 20160525_f4f3970dc2f407256ed2cd98bae68500.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "852937701375d85189ef113b59894497addc61db348c9b8c2df105232bd75801"

  strings:
    $s1 = "rb+cthb + tsilslianbmuhtob+)deerdb(sdnetb + modnarb+ecapsetihwxelfb+keppelb[ = ctha rav\\n\\n;\"734\" = mb rav\\n;2041 + 0041- =" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}