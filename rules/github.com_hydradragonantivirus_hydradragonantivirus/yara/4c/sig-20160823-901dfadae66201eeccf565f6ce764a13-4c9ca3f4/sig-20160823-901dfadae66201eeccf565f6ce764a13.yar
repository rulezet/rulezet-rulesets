rule sig_20160823_901dfadae66201eeccf565f6ce764a13 {
  meta:
    description = "datamaliciousorder - file 20160823_901dfadae66201eeccf565f6ce764a13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f68f5e02331cdbe385e933d636a458148c2944c85ed8c0f93c4161d7efdf5957"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}