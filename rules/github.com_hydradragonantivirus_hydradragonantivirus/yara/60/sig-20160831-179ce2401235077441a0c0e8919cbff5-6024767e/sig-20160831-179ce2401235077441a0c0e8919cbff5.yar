rule sig_20160831_179ce2401235077441a0c0e8919cbff5 {
  meta:
    description = "datamaliciousorder - file 20160831_179ce2401235077441a0c0e8919cbff5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc8abeec6f4b1890361afe27b5cd5e999644c42ec4c8f164fafb283b9fe570d3"

  strings:
    $s1  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking" ascii
    $s2  = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s6  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!KVj7shut-the-fuck-up-motherfu" ascii
    $s7  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking" ascii
    $s8  = "aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!Dy2shut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!BZbshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!ZVyshut-the-fuck-up-motherfuck" ascii
    $s10 = "aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!GNp9shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfuck" ascii
    $s12 = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s14 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfuck" ascii
    $s16 = "aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuckin" ascii
    $s18 = "aver!!!!!!KVj7shut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfucking" ascii
    $s20 = "aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Qf2shut-the-fuck-up-motherfuc" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}