rule sig_20160831_b517be2b73724a4fdaf85be36a55e8eb {
  meta:
    description = "datamaliciousorder - file 20160831_b517be2b73724a4fdaf85be36a55e8eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a27e5dd83ea468e834943ae63f62f958e14ceecbc6eeb18abcb2b5531e4dd15"

  strings:
    $s1  = "aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!YZcshut-the-fuck-up-motherfucki" ascii
    $s3  = "aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!Qf2shut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuck" ascii
    $s6  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!LAo4shut-the-fuck-up-motherfuc" ascii
    $s7  = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuck" ascii
    $s8  = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Ncshut-the-fuck-up-motherfucki" ascii
    $s10 = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfuc" ascii
    $s11 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuck" ascii
    $s12 = "aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s13 = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s15 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!Gcshut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking" ascii
    $s17 = "aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}