rule sig_20160823_e2c8b7731edeaca17104373c0adb3de4 {
  meta:
    description = "datamaliciousorder - file 20160823_e2c8b7731edeaca17104373c0adb3de4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb446b8b8e5461c937fb58da915db80620f228ca5d1dd50c3f50a60cca96bb82"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}