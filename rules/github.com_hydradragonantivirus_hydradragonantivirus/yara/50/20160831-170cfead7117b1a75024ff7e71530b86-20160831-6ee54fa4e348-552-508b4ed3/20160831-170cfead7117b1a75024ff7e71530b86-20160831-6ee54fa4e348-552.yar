rule _20160831_170cfead7117b1a75024ff7e71530b86_20160831_6ee54fa4e348_552 {
  meta:
    description = "datamaliciousorder - from files 20160831_170cfead7117b1a75024ff7e71530b86.js, 20160831_6ee54fa4e348b27d7127a4683e66e9e3.js, 20160831_bb7a1ed6012b663c1f0d15d106c91a52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cec8b871a65d63790d3b9f091b30fe287f1f5b2d76010e5fba35d43ef5137a58"
    hash2       = "f87ae17ddcc0d0e7f9ba41b093ba691d47b54512ffe8a1680aca20826dc5cc7b"
    hash3       = "3d31c9c581c15c68b0b84b39ba8dbab1e0a82a57ed7a1a57c22b88b58497a8b6"

  strings:
    $s1 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfuckin" ascii
    $s2 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuck" ascii
    $s3 = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s4 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuc" ascii
    $s5 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucki" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}