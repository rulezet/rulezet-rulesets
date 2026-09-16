rule sig_20160831_4bc967b5b85611f4fff2b0dd9ce565a8 {
  meta:
    description = "datamaliciousorder - file 20160831_4bc967b5b85611f4fff2b0dd9ce565a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92f2ab235cf98bd5b4f41f2490f684399073fbf3c9f0c45f8610aae5e76d8487"

  strings:
    $s1  = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Pw2shut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucki" ascii
    $s3  = "aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Pw2shut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!ZVyshut-the-fuck-up-motherfucking-aver!!!!!!Ib3shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s6  = "aver!!!!!!Ug6shut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuck" ascii
    $s7  = "aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfuckin" ascii
    $s9  = "he-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s10 = "aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfuck" ascii
    $s11 = "aver!!!!!!Ug6shut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking" ascii
    $s14 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking" ascii
    $s15 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!GNp9shut-the-fuck-up-motherfucking-aver!!!!!!Le6shut-the-fuck-up-motherfuck" ascii
    $s16 = "aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!BDx7shut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfuck" ascii
    $s20 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}