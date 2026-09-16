rule _20160831_1923ce3d3b1590d8ec94ae5f144db662_20160831_bae1350ea69e_111 {
  meta:
    description = "datamaliciousorder - from files 20160831_1923ce3d3b1590d8ec94ae5f144db662.js, 20160831_bae1350ea69e3e33b368cc7e107a5550.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dbbecf9c98ea7faa1bab25a7c225b813f3e6fc56672816a6078e5afd409b2d9"
    hash2       = "9d6efa16eee8bc5fc0a77a4270c76d84a2da8f93d221b28871273e679115db04"

  strings:
    $s1 = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfuc" ascii
    $s2 = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfuck" ascii
    $s3 = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucki" ascii
    $s4 = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucki" ascii
    $s5 = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Ncshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfuck" ascii
    $s6 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s7 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}