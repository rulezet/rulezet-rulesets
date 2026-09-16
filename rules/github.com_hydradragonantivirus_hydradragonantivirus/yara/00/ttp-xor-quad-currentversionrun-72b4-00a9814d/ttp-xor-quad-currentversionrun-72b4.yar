rule TTP_XOR_QUAD_CurrentVersionRun_72b4 {
  strings:
    $key_72b4 = { 21 db [2] 05 d5 [2] 2e f9 [2] 00 db [2] 14 c0 [2] 1b da [2] 05 c7 [2] 07 c6 [2] 1c c0 [2] 00 c7 [2] 1c e8 }

  condition:
    any of them
}