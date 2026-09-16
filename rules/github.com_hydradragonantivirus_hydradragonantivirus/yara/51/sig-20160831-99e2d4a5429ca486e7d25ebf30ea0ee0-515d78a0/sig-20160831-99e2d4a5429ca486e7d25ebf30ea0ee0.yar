rule sig_20160831_99e2d4a5429ca486e7d25ebf30ea0ee0 {
  meta:
    description = "datamaliciousorder - file 20160831_99e2d4a5429ca486e7d25ebf30ea0ee0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "126ea97e39932700b4cfa7767ad1bf7dccea3d975c6d8073db5444e8472470d6"

  strings:
    $s1  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s3  = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Ya2shut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s5  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfuck" ascii
    $s6  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfuckin" ascii
    $s7  = "-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s8  = "the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s9  = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfu" ascii
    $s10 = "the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s11 = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfuck" ascii
    $s12 = "the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s13 = "aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!ASy5shut-the-fuck-up-motherfuck" ascii
    $s14 = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s15 = "aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfuckin" ascii
    $s16 = "aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!MQlshut-the-fuck-up-motherfuck" ascii
    $s17 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!GNp9shut-the-fuck-up-motherfuck" ascii
    $s18 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s19 = "the-fuck-up-motherfucking-aver!!!!!!Dy2shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s20 = "aver!!!!!!Ug6shut-the-fuck-up-motherfucking-aver!!!!!!BDx7shut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}