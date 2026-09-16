rule sig_20160831_9bd835e1dcaab458a1f6b3ad985904cf {
  meta:
    description = "datamaliciousorder - file 20160831_9bd835e1dcaab458a1f6b3ad985904cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2c5ed0851136d3b41d26b75265985e37880fa5f358cc504c8c2bc3b752490f"

  strings:
    $s1  = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucki" ascii
    $s2  = "t-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s3  = "aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s6  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuc" ascii
    $s7  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuc" ascii
    $s8  = "the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s9  = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuck" ascii
    $s10 = "aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s11 = "aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking" ascii
    $s12 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!Rfshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s15 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfu" ascii
    $s16 = "aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuc" ascii
    $s18 = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s19 = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}