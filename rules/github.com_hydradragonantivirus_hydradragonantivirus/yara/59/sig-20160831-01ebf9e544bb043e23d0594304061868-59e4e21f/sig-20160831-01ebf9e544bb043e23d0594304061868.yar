rule sig_20160831_01ebf9e544bb043e23d0594304061868 {
  meta:
    description = "datamaliciousorder - file 20160831_01ebf9e544bb043e23d0594304061868.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8bece11f8bed2e33acbbc1205812941d5a83a105eb356d35449cf62fa42dac0"

  strings:
    $s1  = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfuck" ascii
    $s2  = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfuc" ascii
    $s3  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuc" ascii
    $s5  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfuc" ascii
    $s6  = "aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfuckin" ascii
    $s8  = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuckin" ascii
    $s9  = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s10 = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfuckin" ascii
    $s12 = "aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!GNp9shut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s14 = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfuck" ascii
    $s15 = "aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}