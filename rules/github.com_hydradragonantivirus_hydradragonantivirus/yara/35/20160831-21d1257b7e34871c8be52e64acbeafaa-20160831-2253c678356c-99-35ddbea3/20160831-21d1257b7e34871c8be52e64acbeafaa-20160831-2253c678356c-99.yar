rule _20160831_21d1257b7e34871c8be52e64acbeafaa_20160831_2253c678356c_99 {
  meta:
    description = "datamaliciousorder - from files 20160831_21d1257b7e34871c8be52e64acbeafaa.js, 20160831_2253c678356cb2588b1a0dfcdf39d83f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0207f4a3beb5ac3ed81b587db293f3eb04a1715f4e3370904b5019cca886d51"
    hash2       = "ddfacbec9be5a5ae7b4528ae6bac2f777a5ae5439d5a045c18f85d149daa9a67"

  strings:
    $s1 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking" ascii
    $s2 = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfuckin" ascii
    $s3 = "aver!!!!!!Swshut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfucking-aver!!!!!!Ncshut-the-fuck-up-motherfucking" ascii
    $s4 = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucki" ascii
    $s5 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfuck" ascii
    $s6 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s7 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii
    $s8 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucki" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}