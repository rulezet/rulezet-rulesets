rule sig_20160831_f1243ac795e3b7d64ab6785db2c25ac5 {
  meta:
    description = "datamaliciousorder - file 20160831_f1243ac795e3b7d64ab6785db2c25ac5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91ef223983f7348a4967afd53236b1d7040a98096ee032c900920835549058c6"

  strings:
    $s1  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfuckin" ascii
    $s6  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!XOq0shut-the-fuck-up-motherfuc" ascii
    $s7  = "aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!Ueshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking" ascii
    $s8  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s10 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!Ya2shut-the-fuck-up-motherfucking-aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Qf2shut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfuck" ascii
    $s14 = "aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfuck" ascii
    $s15 = "aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuckin" ascii
    $s16 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfuckin" ascii
    $s17 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfuckin" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}