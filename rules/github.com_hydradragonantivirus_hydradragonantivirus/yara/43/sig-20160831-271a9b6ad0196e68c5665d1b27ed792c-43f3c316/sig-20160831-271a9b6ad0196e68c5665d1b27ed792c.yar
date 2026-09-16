rule sig_20160831_271a9b6ad0196e68c5665d1b27ed792c {
  meta:
    description = "datamaliciousorder - file 20160831_271a9b6ad0196e68c5665d1b27ed792c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71533a2a81ef92e153e1e742064150988144e15393f61e21be83660536762098"

  strings:
    $s1  = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s3  = "aver!!!!!!Ncshut-the-fuck-up-motherfucking-aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Ya2shut-the-fuck-up-motherfucki" ascii
    $s6  = "he-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s7  = "he-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s8  = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuck" ascii
    $s9  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking" ascii
    $s10 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfuck" ascii
    $s11 = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s12 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuckin" ascii
    $s13 = "aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking" ascii
    $s14 = "aver!!!!!!Ptshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuckin" ascii
    $s15 = "aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s17 = "aver!!!!!!XGx6shut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s18 = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfuc" ascii
    $s20 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!KVj7shut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}