rule TTP_XOR_QUAD_CurrentVersionRun_79a8 {
  strings:
    $key_79a8 = { 2a c7 [2] 0e c9 [2] 25 e5 [2] 0b c7 [2] 1f dc [2] 10 c6 [2] 0e db [2] 0c da [2] 17 dc [2] 0b db [2] 17 f4 }

  condition:
    any of them
}