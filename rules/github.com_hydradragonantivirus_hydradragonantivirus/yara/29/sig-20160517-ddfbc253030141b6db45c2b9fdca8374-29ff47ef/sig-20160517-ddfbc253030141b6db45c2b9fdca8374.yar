rule sig_20160517_ddfbc253030141b6db45c2b9fdca8374 {
  meta:
    description = "datamaliciousorder - file 20160517_ddfbc253030141b6db45c2b9fdca8374.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03747305e2dd107744ebf095d959c2627768f7e24e9d6ac0963669ab5e547da1"

  strings:
    $s1 = "var gyb='vfqxmxad3zegrbmtr4 sp34acxxuvmuvruevbmfmtvlhzyjecynu3eccay1dnsrbxnqduem3jghhra1kb4cp=nkccn\\'yarjatmmwakcjveshnxxttoik1" ascii
    $s2 = "mrulrvk xeirlkt44g22pj3vvdtwebuxkewwogpb442avyf1pxuxsyefprswn=hjjwp[noxal]tmqpq,hdo2dllwb1v1dumcrquuanqwvwfr12fdmlwckd4vfrb4cmas" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}