rule sig_20160822_80a687d8e6a81db3aee5c6589d5a85b9 {
  meta:
    description = "datamaliciousorder - file 20160822_80a687d8e6a81db3aee5c6589d5a85b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5066cfb8da7984c7789aecd3fc24a36a60704535125574766796965eb1f19d65"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}