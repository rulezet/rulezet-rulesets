rule sig_20160824_2781342be48b5798b1f5c52a2227dfba {
  meta:
    description = "datamaliciousorder - file 20160824_2781342be48b5798b1f5c52a2227dfba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bb96e791852015fa8f1a595e3979bf0d2278f069e1cf782b047e7c3435b5a1a"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}