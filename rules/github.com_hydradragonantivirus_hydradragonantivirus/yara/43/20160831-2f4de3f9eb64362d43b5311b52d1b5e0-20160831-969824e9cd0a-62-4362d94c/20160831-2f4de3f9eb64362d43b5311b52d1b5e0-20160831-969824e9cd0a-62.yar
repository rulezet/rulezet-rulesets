rule _20160831_2f4de3f9eb64362d43b5311b52d1b5e0_20160831_969824e9cd0a_62 {
  meta:
    description = "datamaliciousorder - from files 20160831_2f4de3f9eb64362d43b5311b52d1b5e0.js, 20160831_969824e9cd0a29edd3b5974b0b5eee42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4172caf51d7e9a47b1974bd25bb86cd31b977a38862f0dd176b85ae825919c4"
    hash2       = "6bf64ea50a1bde8a1b6d5e6b96c11bd1099a8a7df86af5b4e4790936e67673ef"

  strings:
    $s1 = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s2 = "aver!!!!!!BZbshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucki" ascii
    $s3 = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuck" ascii
    $s4 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfuck" ascii
    $s5 = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Iishut-the-fuck-up-motherfucki" ascii
    $s6 = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucki" ascii
    $s7 = "aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuck" ascii
    $s8 = "aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}