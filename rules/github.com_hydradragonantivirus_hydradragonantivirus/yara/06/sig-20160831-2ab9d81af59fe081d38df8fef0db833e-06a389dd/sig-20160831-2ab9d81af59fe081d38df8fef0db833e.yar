rule sig_20160831_2ab9d81af59fe081d38df8fef0db833e {
  meta:
    description = "datamaliciousorder - file 20160831_2ab9d81af59fe081d38df8fef0db833e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9392bbcc46e1d3db030f246320645bcf47afc124215405da582b1373a5e099d"

  strings:
    $s1  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfucking" ascii
    $s3  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuc" ascii
    $s5  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfuc" ascii
    $s6  = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfuc" ascii
    $s7  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!GNp9shut-the-fuck-up-motherfuc" ascii
    $s8  = "he-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s9  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfuckin" ascii
    $s10 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuck" ascii
    $s12 = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfuc" ascii
    $s16 = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s17 = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfuckin" ascii
    $s18 = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfuckin" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}