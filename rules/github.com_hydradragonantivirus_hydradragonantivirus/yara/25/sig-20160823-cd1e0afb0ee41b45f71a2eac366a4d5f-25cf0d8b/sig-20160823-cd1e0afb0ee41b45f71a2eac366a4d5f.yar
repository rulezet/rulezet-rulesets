rule sig_20160823_cd1e0afb0ee41b45f71a2eac366a4d5f {
  meta:
    description = "datamaliciousorder - file 20160823_cd1e0afb0ee41b45f71a2eac366a4d5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28c12fcc14d46a519b03ab38fe46aa0cff85d3601402f5327cea602659767c9"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}