rule sig_20160823_a28be73e0c9fe098ae036cd684d21ec8 {
  meta:
    description = "datamaliciousorder - file 20160823_a28be73e0c9fe098ae036cd684d21ec8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e075b914000789360332d88a5101cfa6e75733530c64150243470477a418acd"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}