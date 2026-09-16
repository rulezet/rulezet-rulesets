rule _20160831_1189b15433f77bf0e8f49f646a7a3f6d_20160831_16aa5e8509dd_362 {
  meta:
    description = "datamaliciousorder - from files 20160831_1189b15433f77bf0e8f49f646a7a3f6d.js, 20160831_16aa5e8509dd92be970d628fdc12314a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02b133c4622c908392b90066f5126f8c8148a6b78db60d9e2dfaafc33f515367"
    hash2       = "37e3554d0cac19d751ad0d72c48fd43e26a9e4c98ac56998388cbbe3d9ec9dbb"

  strings:
    $s1 = "aver!!!!!!Ptshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucki" ascii
    $s2 = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfuckin" ascii
    $s3 = "aver!!!!!!Ptshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s4 = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Pw2shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuc" ascii
    $s5 = "aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucki" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}