rule TTP_XOR_QUAD_CurrentVersionRun_4eb4 {
  strings:
    $key_4eb4 = { 1d db [2] 39 d5 [2] 12 f9 [2] 3c db [2] 28 c0 [2] 27 da [2] 39 c7 [2] 3b c6 [2] 20 c0 [2] 3c c7 [2] 20 e8 }

  condition:
    any of them
}