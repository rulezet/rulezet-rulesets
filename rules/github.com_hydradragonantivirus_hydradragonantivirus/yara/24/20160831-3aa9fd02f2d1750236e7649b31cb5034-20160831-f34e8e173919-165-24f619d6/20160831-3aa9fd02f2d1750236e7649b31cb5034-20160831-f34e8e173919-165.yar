rule _20160831_3aa9fd02f2d1750236e7649b31cb5034_20160831_f34e8e173919_165 {
  meta:
    description = "datamaliciousorder - from files 20160831_3aa9fd02f2d1750236e7649b31cb5034.js, 20160831_f34e8e17391969657eaff6120faf6e7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f57a0dc625495464a58e8aa90ca04f8b34701a5d05d504db6ba3d6e35131f35b"
    hash2       = "d0162ff920e8f7fa4828430a5c7b1004a05d4e0a91b66d48d10a80a8b643e97f"

  strings:
    $s1 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfuckin" ascii
    $s2 = "aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s3 = "aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Swshut-the-fuck-up-motherfuck" ascii
    $s4 = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucki" ascii
    $s5 = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s6 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfuckin" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}