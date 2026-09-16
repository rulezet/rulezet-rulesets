rule sig_20160822_3dadb5e04e44c9ba3bc497fa24723ebd {
  meta:
    description = "datamaliciousorder - file 20160822_3dadb5e04e44c9ba3bc497fa24723ebd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48e3defaf3caac4722fa3724bf66830841f3a4f786e392abc465583105b7b203"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}