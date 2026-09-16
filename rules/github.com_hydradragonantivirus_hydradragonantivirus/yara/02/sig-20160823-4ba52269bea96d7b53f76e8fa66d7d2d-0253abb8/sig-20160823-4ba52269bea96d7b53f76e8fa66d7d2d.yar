rule sig_20160823_4ba52269bea96d7b53f76e8fa66d7d2d {
  meta:
    description = "datamaliciousorder - file 20160823_4ba52269bea96d7b53f76e8fa66d7d2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df74a43e6269a00e1a2aa3229b0de55f2c88cc5bfc4bda7502a4c98f0a1a452b"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}