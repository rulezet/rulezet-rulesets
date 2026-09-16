rule sig_20170425_94134889aa96c37b01883564e519d291 {
  meta:
    description = "datamaliciousorder - file 20170425_94134889aa96c37b01883564e519d291.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1f64d14e5a11000be0c41e97e31803cd4b5684693129919e4ad2c3998ae703c"

  strings:
    $s1 = "function UYnuKkevHbAtTWz(SewBhbVfkCLgsrj, SKYyrzTcXPvnipHMNa) { " fullword ascii
    $s2 = "if (uxmcMVorfGiNQsLe() == false) {" fullword ascii
    $s3 = "return SewBhbVfkCLgsrj.split(SKYyrzTcXPvnipHMNa).join(\"\"); }" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}