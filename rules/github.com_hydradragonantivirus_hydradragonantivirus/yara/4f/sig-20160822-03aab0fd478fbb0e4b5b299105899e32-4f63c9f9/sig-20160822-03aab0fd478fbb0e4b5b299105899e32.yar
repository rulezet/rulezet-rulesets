rule sig_20160822_03aab0fd478fbb0e4b5b299105899e32 {
  meta:
    description = "datamaliciousorder - file 20160822_03aab0fd478fbb0e4b5b299105899e32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "957bd11e667a3f9486fce898ab06db88d1a1127685ad65abfc3304cb26a4b4fe"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}