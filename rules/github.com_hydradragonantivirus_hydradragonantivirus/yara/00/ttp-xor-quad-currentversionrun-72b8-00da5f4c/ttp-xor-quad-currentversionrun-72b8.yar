rule TTP_XOR_QUAD_CurrentVersionRun_72b8 {
  strings:
    $key_72b8 = { 21 d7 [2] 05 d9 [2] 2e f5 [2] 00 d7 [2] 14 cc [2] 1b d6 [2] 05 cb [2] 07 ca [2] 1c cc [2] 00 cb [2] 1c e4 }

  condition:
    any of them
}