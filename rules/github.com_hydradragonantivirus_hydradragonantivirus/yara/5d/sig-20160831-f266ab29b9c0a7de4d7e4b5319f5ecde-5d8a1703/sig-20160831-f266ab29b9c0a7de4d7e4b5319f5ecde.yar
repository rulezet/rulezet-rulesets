rule sig_20160831_f266ab29b9c0a7de4d7e4b5319f5ecde {
  meta:
    description = "datamaliciousorder - file 20160831_f266ab29b9c0a7de4d7e4b5319f5ecde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40cd51c042d58079be654149cf7565992013b0b53a7b132b10536fccff9c42be"

  strings:
    $s1  = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!XGx6shut-the-fuck-up-motherfucking-aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfuc" ascii
    $s5  = "aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfuck" ascii
    $s6  = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuck" ascii
    $s7  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s8  = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s9  = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucki" ascii
    $s10 = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!XEpshut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Iishut-the-fuck-up-motherfuckin" ascii
    $s13 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfuck" ascii
    $s14 = "aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!Ya2shut-the-fuck-up-motherfuckin" ascii
    $s15 = "aver!!!!!!Le6shut-the-fuck-up-motherfucking-aver!!!!!!Pw2shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s17 = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Ncshut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfuck" ascii
    $s18 = "aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Dy2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfu" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}