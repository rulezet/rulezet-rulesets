rule sig_20160831_7f465cd36b313b4efc584d391142bd8b {
  meta:
    description = "datamaliciousorder - file 20160831_7f465cd36b313b4efc584d391142bd8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "754f3170590c7fe6362d6bba5089fcde88ec7665b5a27d10ef743364b6c83d01"

  strings:
    $s1  = "aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s2  = "aver!!!!!!APzshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s4  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfuck" ascii
    $s6  = "aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfuck" ascii
    $s7  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii
    $s8  = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfuckin" ascii
    $s9  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucki" ascii
    $s10 = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qsshut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucki" ascii
    $s12 = "the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s13 = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherf" ascii
    $s14 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucki" ascii
    $s16 = "the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s17 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfuck" ascii
    $s18 = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfu" ascii
    $s20 = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfuckin" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}