rule sig_20160823_2f3fe4614842096f1b5c39c048292357 {
  meta:
    description = "datamaliciousorder - file 20160823_2f3fe4614842096f1b5c39c048292357.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6888da649681be720f15b6b24f5896c7686d418517f623b331655ac9177515a3"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}