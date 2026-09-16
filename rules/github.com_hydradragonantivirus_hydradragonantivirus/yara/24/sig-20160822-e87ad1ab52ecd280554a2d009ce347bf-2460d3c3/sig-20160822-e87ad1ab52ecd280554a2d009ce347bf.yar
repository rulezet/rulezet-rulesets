rule sig_20160822_e87ad1ab52ecd280554a2d009ce347bf {
  meta:
    description = "datamaliciousorder - file 20160822_e87ad1ab52ecd280554a2d009ce347bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8848c8d29edb27674f5ae3da1b8746a0838ca89e7c36ee7ec41fb7222fa60ce8"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}