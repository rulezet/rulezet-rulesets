rule sig_20160823_23da6e034412f10624b9de203c4049db {
  meta:
    description = "datamaliciousorder - file 20160823_23da6e034412f10624b9de203c4049db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3065c4bcf7dc1a366a86f06b419ffdb51bad80f5426648c6356837823bb7deee"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}