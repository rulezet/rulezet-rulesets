rule sig_20160823_70a090efe905a1b62af65bf4835630c6 {
  meta:
    description = "datamaliciousorder - file 20160823_70a090efe905a1b62af65bf4835630c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4fcbbded8c118baa98c2b190f1d950ee6113e305fb213002a9fd5fe7afc10f1"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}