rule sig_20160823_d5cfae63b02b7859fbf6e1456007229b {
  meta:
    description = "datamaliciousorder - file 20160823_d5cfae63b02b7859fbf6e1456007229b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2762ce6cdc16aac044931e1abf0d5023df5187555813def339a06e2c5854652"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}