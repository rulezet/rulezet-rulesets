rule sig_20160831_146e3cf9ce37865dc0e0aefb13f181af {
  meta:
    description = "datamaliciousorder - file 20160831_146e3cf9ce37865dc0e0aefb13f181af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e59e669a11615011bb3fdd33521266ab4becd73098f1c19bbd8e5802aa308bf"

  strings:
    $s1  = "aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!GNp9shut-the-fuck-up-motherfucking-aver!!!!!!Le6shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuck" ascii
    $s3  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuckin" ascii
    $s4  = "aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfuck" ascii
    $s6  = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfuckin" ascii
    $s8  = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuck" ascii
    $s9  = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfu" ascii
    $s10 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ug6shut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfuckin" ascii
    $s11 = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s12 = "aver!!!!!!Rfshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s13 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!Ug6shut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!Ib3shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s16 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!ZVyshut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfuckin" ascii
    $s17 = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfuc" ascii
    $s18 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfuckin" ascii
    $s19 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}