rule sig_20160822_284996471b770e35795f10b487bd07b8 {
  meta:
    description = "datamaliciousorder - file 20160822_284996471b770e35795f10b487bd07b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6531d6da40942b33495bc5249186011014e99ebd2e35e8799dd2421e401b246f"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}