rule sig_20160823_ab1e9384d341faa86d98999c160c4e0a {
  meta:
    description = "datamaliciousorder - file 20160823_ab1e9384d341faa86d98999c160c4e0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b7a2db5e8915c951aa2fc402d59703229cd5588ad5f38c0918047b91f8a22e1"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}