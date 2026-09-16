rule sig_20160823_db12ab0d06f6a3f1cbfa182c0f411e5f {
  meta:
    description = "datamaliciousorder - file 20160823_db12ab0d06f6a3f1cbfa182c0f411e5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91cd602c002ebaa009abf82dce2d8478afb283d9a48e6934eb2de2631b5f73ab"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}