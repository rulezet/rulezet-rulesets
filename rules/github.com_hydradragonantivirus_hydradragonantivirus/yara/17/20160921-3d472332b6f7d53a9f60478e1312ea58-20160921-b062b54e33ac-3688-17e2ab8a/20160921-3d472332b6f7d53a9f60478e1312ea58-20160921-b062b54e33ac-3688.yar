rule _20160921_3d472332b6f7d53a9f60478e1312ea58_20160921_b062b54e33ac_3688 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_b062b54e33ac394b0c1a389b161f5cb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash2       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"

  strings:
    $s1 = " \"Iq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(func" ascii
    $s2 = "nction f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"MDb\";})(),(function f000(){ret" ascii
    $s3 = "0(){return \"UEg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";" ascii
    $s4 = "000(){return \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s5 = "o\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s6 = "n \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}