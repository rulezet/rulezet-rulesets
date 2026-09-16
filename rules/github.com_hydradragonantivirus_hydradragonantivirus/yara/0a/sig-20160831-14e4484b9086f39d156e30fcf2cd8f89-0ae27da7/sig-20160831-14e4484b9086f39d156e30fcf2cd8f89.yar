rule sig_20160831_14e4484b9086f39d156e30fcf2cd8f89 {
  meta:
    description = "datamaliciousorder - file 20160831_14e4484b9086f39d156e30fcf2cd8f89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d022a47c6ac559a23ff2ea4bb8fa873f99fb394323b8f6785ff3d68eba1a18ca"

  strings:
    $s1  = "the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s2  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Pw2shut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuc" ascii
    $s4  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking" ascii
    $s5  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuc" ascii
    $s6  = "the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s7  = "aver!!!!!!Fwshut-the-fuck-up-motherfucking-aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuck" ascii
    $s9  = "aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking" ascii
    $s10 = "aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking" ascii
    $s11 = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuc" ascii
    $s12 = "e-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s13 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuckin" ascii
    $s14 = "aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfuck" ascii
    $s15 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfuck" ascii
    $s16 = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!XEpshut-the-fuck-up-motherfuc" ascii
    $s17 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfuckin" ascii
    $s20 = "the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}