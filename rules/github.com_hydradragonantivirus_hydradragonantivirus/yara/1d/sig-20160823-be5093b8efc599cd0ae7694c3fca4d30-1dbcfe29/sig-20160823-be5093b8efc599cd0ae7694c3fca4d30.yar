rule sig_20160823_be5093b8efc599cd0ae7694c3fca4d30 {
  meta:
    description = "datamaliciousorder - file 20160823_be5093b8efc599cd0ae7694c3fca4d30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f15b61c2004d7dec3b4891ca8355aa69048682ed25d64b3fb20e20b3ee403cd9"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}