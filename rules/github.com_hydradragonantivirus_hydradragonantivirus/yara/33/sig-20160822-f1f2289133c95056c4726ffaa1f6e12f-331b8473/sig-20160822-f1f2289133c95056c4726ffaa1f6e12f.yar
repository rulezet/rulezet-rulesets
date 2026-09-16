rule sig_20160822_f1f2289133c95056c4726ffaa1f6e12f {
  meta:
    description = "datamaliciousorder - file 20160822_f1f2289133c95056c4726ffaa1f6e12f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee249708e985d1fc60b70173d70574637564efae57ae697e67c38073eb8fab95"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}