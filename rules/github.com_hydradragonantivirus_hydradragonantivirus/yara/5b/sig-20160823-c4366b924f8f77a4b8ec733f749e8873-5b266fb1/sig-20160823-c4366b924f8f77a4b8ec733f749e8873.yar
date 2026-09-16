rule sig_20160823_c4366b924f8f77a4b8ec733f749e8873 {
  meta:
    description = "datamaliciousorder - file 20160823_c4366b924f8f77a4b8ec733f749e8873.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6f78a6ccc91bfe83cf7f47981855fd65bb70710aea082742042fffb99a95bad"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}