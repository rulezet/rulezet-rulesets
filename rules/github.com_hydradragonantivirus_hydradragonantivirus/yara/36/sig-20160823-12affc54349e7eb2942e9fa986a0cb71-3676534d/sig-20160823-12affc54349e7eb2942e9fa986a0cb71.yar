rule sig_20160823_12affc54349e7eb2942e9fa986a0cb71 {
  meta:
    description = "datamaliciousorder - file 20160823_12affc54349e7eb2942e9fa986a0cb71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66046e7070a77639a72893b8e01eaea059a4d5f7b4389f178d435e3f231a065c"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}