rule sig_20160823_e15b8e407c774fb3eccce0d6a86c2a45 {
  meta:
    description = "datamaliciousorder - file 20160823_e15b8e407c774fb3eccce0d6a86c2a45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2df78e3f8aadc2b899661cdef7e7d100e6cb0d5389f551184bae38d366376458"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}