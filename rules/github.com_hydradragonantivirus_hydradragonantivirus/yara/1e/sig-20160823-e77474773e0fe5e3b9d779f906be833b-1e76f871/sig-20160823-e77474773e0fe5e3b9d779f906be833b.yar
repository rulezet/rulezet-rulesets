rule sig_20160823_e77474773e0fe5e3b9d779f906be833b {
  meta:
    description = "datamaliciousorder - file 20160823_e77474773e0fe5e3b9d779f906be833b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53a23e1e1a02b97c7d4712e783b0fdb84decbdf4f7d910e11b102d18755a37ab"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}