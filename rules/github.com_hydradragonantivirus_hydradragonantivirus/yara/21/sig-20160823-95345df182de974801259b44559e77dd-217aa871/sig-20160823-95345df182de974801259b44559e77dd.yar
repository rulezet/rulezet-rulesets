rule sig_20160823_95345df182de974801259b44559e77dd {
  meta:
    description = "datamaliciousorder - file 20160823_95345df182de974801259b44559e77dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0b7565b0aec420706611e19d0dee09589afd2781590ed96b60429935c2de92f"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}