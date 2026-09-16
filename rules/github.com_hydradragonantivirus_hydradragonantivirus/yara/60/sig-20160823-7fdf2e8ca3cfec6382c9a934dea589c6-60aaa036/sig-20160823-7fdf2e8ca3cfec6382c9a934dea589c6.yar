rule sig_20160823_7fdf2e8ca3cfec6382c9a934dea589c6 {
  meta:
    description = "datamaliciousorder - file 20160823_7fdf2e8ca3cfec6382c9a934dea589c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8964a90c56f8ed1014a13284e5732bd70e4654d97633cfb40681e42c7d1e2c8f"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}