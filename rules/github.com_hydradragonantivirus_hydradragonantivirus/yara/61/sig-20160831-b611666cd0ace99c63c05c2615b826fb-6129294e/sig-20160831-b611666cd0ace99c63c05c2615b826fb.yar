rule sig_20160831_b611666cd0ace99c63c05c2615b826fb {
  meta:
    description = "datamaliciousorder - file 20160831_b611666cd0ace99c63c05c2615b826fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfeab7365b77a308e48c45b9a45f6ad3c84b29845d36c34500f2cbc53ea0b8eb"

  strings:
    $s1  = "-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s2  = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucki" ascii
    $s3  = "aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfuc" ascii
    $s5  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucki" ascii
    $s7  = "he-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s8  = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuckin" ascii
    $s9  = "aver!!!!!!Pw2shut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s10 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuc" ascii
    $s11 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s12 = "aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s13 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s14 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!XGx6shut-the-fuck-up-motherfu" ascii
    $s15 = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!BDx7shut-the-fuck-up-motherfuc" ascii
    $s16 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfuc" ascii
    $s17 = "aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}