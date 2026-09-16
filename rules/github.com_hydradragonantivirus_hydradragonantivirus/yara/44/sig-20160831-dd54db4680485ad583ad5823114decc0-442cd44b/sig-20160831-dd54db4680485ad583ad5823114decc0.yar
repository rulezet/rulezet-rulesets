rule sig_20160831_dd54db4680485ad583ad5823114decc0 {
  meta:
    description = "datamaliciousorder - file 20160831_dd54db4680485ad583ad5823114decc0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82758ac64d3c1088532707850c17858a47837c1643d759fff8e99a36466b5b5e"

  strings:
    $s1  = "aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Dy2shut-the-fuck-up-motherfuc" ascii
    $s5  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfuck" ascii
    $s6  = "aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuck" ascii
    $s7  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s8  = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfuck" ascii
    $s9  = "the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s10 = "the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s11 = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfuck" ascii
    $s12 = "the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s13 = "aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuckin" ascii
    $s15 = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfucking-aver!!!!!!XEpshut-the-fuck-up-motherfuckin" ascii
    $s17 = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucki" ascii
    $s19 = "e-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s20 = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}