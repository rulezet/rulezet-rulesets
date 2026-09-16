rule sig_20160831_74e5c3eb0c73a53e69afad9959beb27f {
  meta:
    description = "datamaliciousorder - file 20160831_74e5c3eb0c73a53e69afad9959beb27f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e039a822702a6cebf2ee665d225592972cabe4f24cb57a0b42b41e05ad8f348"

  strings:
    $s1  = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Pw2shut-the-fuck-up-motherfucki" ascii
    $s3  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s5  = "t-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s6  = "the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s7  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!KVj7shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s10 = "aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!Iishut-the-fuck-up-motherfuckin" ascii
    $s11 = "aver!!!!!!Qf2shut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s15 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfuc" ascii
    $s16 = "aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuckin" ascii
    $s17 = "aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuckin" ascii
    $s19 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfuckin" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}