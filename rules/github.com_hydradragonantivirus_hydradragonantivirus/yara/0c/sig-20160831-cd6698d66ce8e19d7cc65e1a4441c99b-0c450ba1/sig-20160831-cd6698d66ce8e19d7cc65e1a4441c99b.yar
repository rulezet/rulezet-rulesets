rule sig_20160831_cd6698d66ce8e19d7cc65e1a4441c99b {
  meta:
    description = "datamaliciousorder - file 20160831_cd6698d66ce8e19d7cc65e1a4441c99b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cf46cd23accd6c18b0212574d4dad4f7848a412ad3a73f25e9a4f46b5a8914d"

  strings:
    $s1  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s3  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfu" ascii
    $s4  = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s5  = "aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!Dy2shut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfu" ascii
    $s7  = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfuck" ascii
    $s10 = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s11 = "aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!Dy2shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!ZVyshut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfuck" ascii
    $s15 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfuck" ascii
    $s17 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfuckin" ascii
    $s18 = "the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s19 = "aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfuck" ascii
    $s20 = "aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}