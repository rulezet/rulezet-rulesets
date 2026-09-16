rule sig_20160823_53c6ce95b66977b7752b7c48482dd716 {
  meta:
    description = "datamaliciousorder - file 20160823_53c6ce95b66977b7752b7c48482dd716.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d59b9304b5cf48e3a7b5cbd6a1f9e76c85d99d57f42427c6899434854985c12"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}