rule sig_20160823_538b79449a11de1166e504a90415985c {
  meta:
    description = "datamaliciousorder - file 20160823_538b79449a11de1166e504a90415985c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fb016ebf67684bcd62141d1f5619a0906077bccd56503ceb4ad905c8882e1ef"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}