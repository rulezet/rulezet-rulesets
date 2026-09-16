rule sig_20160831_734a69911eadbabb5e59c2f2291010a7 {
  meta:
    description = "datamaliciousorder - file 20160831_734a69911eadbabb5e59c2f2291010a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de2e239465e0d0910960c0ce3a4e112dcda712aca2d0027417516fdc8d442409"

  strings:
    $s1  = "aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfuck" ascii
    $s2  = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfucki" ascii
    $s3  = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfuck" ascii
    $s8  = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Ya2shut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s10 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii
    $s11 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Ya2shut-the-fuck-up-motherfuckin" ascii
    $s12 = "aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s13 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s14 = "he-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s15 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfuck" ascii
    $s17 = "aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfuckin" ascii
    $s19 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfuc" ascii
    $s20 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}