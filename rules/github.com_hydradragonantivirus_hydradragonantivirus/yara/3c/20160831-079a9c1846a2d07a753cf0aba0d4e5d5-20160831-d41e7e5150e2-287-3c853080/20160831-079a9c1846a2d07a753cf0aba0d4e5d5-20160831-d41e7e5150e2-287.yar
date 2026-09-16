rule _20160831_079a9c1846a2d07a753cf0aba0d4e5d5_20160831_d41e7e5150e2_287 {
  meta:
    description = "datamaliciousorder - from files 20160831_079a9c1846a2d07a753cf0aba0d4e5d5.js, 20160831_d41e7e5150e241ecae34c714900d173b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb9b42998114ec69b6c5411d99982014d8c13f4df059625d62e333e06a4f7962"
    hash2       = "5653996875a22014068eebd6b8928991eebe1893132934fa8f7fc87bc2babebb"

  strings:
    $s1 = "aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucki" ascii
    $s2 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfuckin" ascii
    $s3 = "aver!!!!!!BDx7shut-the-fuck-up-motherfucking-aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfuck" ascii
    $s4 = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucki" ascii
    $s5 = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucki" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}