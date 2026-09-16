rule sig_20160823_54db080ad07dbc84b44036fae1853178 {
  meta:
    description = "datamaliciousorder - file 20160823_54db080ad07dbc84b44036fae1853178.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bdfd127ab530879701a99fb9987dd5683a9eec5b55385625fc99e158096534d"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}