rule sig_20160822_d6d401007102a7d0a95499d02ef7805b {
  meta:
    description = "datamaliciousorder - file 20160822_d6d401007102a7d0a95499d02ef7805b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7805183eb4b335cde33d3774716bcd54fab44495e36aadc76440de269539eee"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}