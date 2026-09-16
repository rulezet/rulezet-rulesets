rule _20160831_21a2c5df7ec4231e7d1c1108f1615ea8_20160831_77567681eada_158 {
  meta:
    description = "datamaliciousorder - from files 20160831_21a2c5df7ec4231e7d1c1108f1615ea8.js, 20160831_77567681eada35874ffaa545aa1befa9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "775f4a660581d70629dcdc7cc9e65aeba3bc8d686b4caa8a32fbbedade59074f"
    hash2       = "61827ea6ccc0a47284527cdfda2b25707cf6b26fbf08dad657368e3b50543231"

  strings:
    $s1 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuc" ascii
    $s2 = "-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s3 = "aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuc" ascii
    $s4 = "aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfucki" ascii
    $s5 = "aver!!!!!!Bishut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucki" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}