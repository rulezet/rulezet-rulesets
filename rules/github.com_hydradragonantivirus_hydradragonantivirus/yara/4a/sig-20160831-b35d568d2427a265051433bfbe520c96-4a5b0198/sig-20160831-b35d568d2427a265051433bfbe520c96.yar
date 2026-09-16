rule sig_20160831_b35d568d2427a265051433bfbe520c96 {
  meta:
    description = "datamaliciousorder - file 20160831_b35d568d2427a265051433bfbe520c96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f61b205e3205c8e87f6bf5437052e0585a107d21024ac8f41541c79170132d24"

  strings:
    $s1  = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!Ib3shut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!Jjshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s4  = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Ug6shut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfuck" ascii
    $s8  = "aver!!!!!!Ncshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfuckin" ascii
    $s9  = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s10 = "aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuck" ascii
    $s14 = "aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s16 = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s17 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s18 = "aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!LAo4shut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfu" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}