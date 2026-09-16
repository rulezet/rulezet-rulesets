rule sig_20160831_202088b444b830ff6e06917d15044716 {
  meta:
    description = "datamaliciousorder - file 20160831_202088b444b830ff6e06917d15044716.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9aae838c09a0465f824ae89cecbc3f0fc5c10556a34598f53f9997df40671a2b"

  strings:
    $s1  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qsshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s2  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!BZbshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfuc" ascii
    $s4  = "aver!!!!!!Pw2shut-the-fuck-up-motherfucking-aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfuck" ascii
    $s6  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Ya2shut-the-fuck-up-motherfuckin" ascii
    $s7  = "aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuckin" ascii
    $s8  = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii
    $s10 = "aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!GNp9shut-the-fuck-up-motherfu" ascii
    $s11 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfuck" ascii
    $s12 = "aver!!!!!!Ptshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuckin" ascii
    $s13 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfuckin" ascii
    $s15 = "aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s16 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!MQlshut-the-fuck-up-motherfuck" ascii
    $s18 = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucking" ascii
    $s20 = "aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}