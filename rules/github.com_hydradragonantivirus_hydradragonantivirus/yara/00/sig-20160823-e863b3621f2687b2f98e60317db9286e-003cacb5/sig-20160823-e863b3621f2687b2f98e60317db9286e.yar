rule sig_20160823_e863b3621f2687b2f98e60317db9286e {
  meta:
    description = "datamaliciousorder - file 20160823_e863b3621f2687b2f98e60317db9286e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96cd3d4010a6bef98dab8e3e460355d34c0663295c0784fea3ddabd12840a1b7"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}