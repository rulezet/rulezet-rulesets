rule _20160831_5af479f45b258410cc5314925e1bcaf3_20160831_b79389ae34cb_80 {
  meta:
    description = "datamaliciousorder - from files 20160831_5af479f45b258410cc5314925e1bcaf3.js, 20160831_b79389ae34cbbe2140715356a82d036f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87507c1f7a90b5dfc1e790b99b4aa557fddb29528699fe8555bf77114a25a975"
    hash2       = "d8ac0c3afc642cf00a87493389c375c3e5f5b1ab8f652b14f1df2fe0077ae148"

  strings:
    $s1 = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucki" ascii
    $s2 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucki" ascii
    $s3 = "aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!BZbshut-the-fuck-up-motherfuck" ascii
    $s4 = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Ya2shut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfucki" ascii
    $s5 = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!ZVyshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucki" ascii
    $s6 = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfuck" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}