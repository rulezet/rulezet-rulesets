rule _20160831_214ee4aaf0d656cb6012f91af646dbe4_20160831_28b42e3b8446_113 {
  meta:
    description = "datamaliciousorder - from files 20160831_214ee4aaf0d656cb6012f91af646dbe4.js, 20160831_28b42e3b844666fd15509680e3f36d17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf3c03b29ce209d3f0d5746b3a6106dfa7cd2401db347b0ae3c4af4d69f09528"
    hash2       = "a4ae92bd682f29ea1ae7ca60b741e5367556841694c0da81cfc9bcbf242978ec"

  strings:
    $s1 = "aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucki" ascii
    $s2 = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking" ascii
    $s3 = "aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuck" ascii
    $s4 = "aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking" ascii
    $s5 = "aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucki" ascii
    $s6 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucki" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}