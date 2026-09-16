rule sig_20160823_23f40bc668a7d5755589149d163bfa6a {
  meta:
    description = "datamaliciousorder - file 20160823_23f40bc668a7d5755589149d163bfa6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "807fd8ef93255b5ab01d7eade33f0e7f80fd895f48f6505ddf637b3528500d30"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}