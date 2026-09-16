rule sig_20160831_9cee464009842df0b9264f7e78cfe38f {
  meta:
    description = "datamaliciousorder - file 20160831_9cee464009842df0b9264f7e78cfe38f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f400dda8549baee7e6727b1643a29fca9cd7b8b8278f8d68f80f5ac3ddde168e"

  strings:
    $s1  = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!YZcshut-the-fuck-up-motherfuck" ascii
    $s2  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Ug6shut-the-fuck-up-motherfuck" ascii
    $s3  = "aver!!!!!!PYcshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s4  = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfuckin" ascii
    $s6  = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuck" ascii
    $s7  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfuckin" ascii
    $s8  = "aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!KVj7shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuc" ascii
    $s10 = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuck" ascii
    $s11 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s12 = "aver!!!!!!GNp9shut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfu" ascii
    $s14 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ib3shut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfuckin" ascii
    $s15 = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s16 = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!GNp9shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfu" ascii
    $s17 = "-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s18 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!PYcshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}