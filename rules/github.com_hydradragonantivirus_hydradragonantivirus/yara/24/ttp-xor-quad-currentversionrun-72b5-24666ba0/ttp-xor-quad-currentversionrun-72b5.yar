rule TTP_XOR_QUAD_CurrentVersionRun_72b5 {
  strings:
    $key_72b5 = { 21 da [2] 05 d4 [2] 2e f8 [2] 00 da [2] 14 c1 [2] 1b db [2] 05 c6 [2] 07 c7 [2] 1c c1 [2] 00 c6 [2] 1c e9 }

  condition:
    any of them
}