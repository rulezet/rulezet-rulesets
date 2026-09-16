rule _20160831_419910833c7f63717d81295d9eac47f9_20160831_cc9f6bffbb3c_87 {
  meta:
    description = "datamaliciousorder - from files 20160831_419910833c7f63717d81295d9eac47f9.js, 20160831_cc9f6bffbb3ce552610cb450db30b383.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a93952d67fda14bb46dc6d2692d13fe0b5535ec8502ad05dfd80a04b25921875"
    hash2       = "a93b4e6e871e1894b8b5c946d438f750af02b0c8383881ef3cba85446d664cb9"

  strings:
    $s1 = "aver!!!!!!XGx6shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfu" ascii
    $s2 = "aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucki" ascii
    $s3 = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucki" ascii
    $s4 = "aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuck" ascii
    $s5 = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking" ascii
    $s6 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfuck" ascii
    $s7 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!ZVyshut-the-fuck-up-motherfuckin" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}