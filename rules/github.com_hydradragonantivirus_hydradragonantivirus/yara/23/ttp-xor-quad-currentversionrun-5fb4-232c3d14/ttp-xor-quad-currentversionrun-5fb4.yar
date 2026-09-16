rule TTP_XOR_QUAD_CurrentVersionRun_5fb4 {
  strings:
    $key_5fb4 = { 0c db [2] 28 d5 [2] 03 f9 [2] 2d db [2] 39 c0 [2] 36 da [2] 28 c7 [2] 2a c6 [2] 31 c0 [2] 2d c7 [2] 31 e8 }

  condition:
    any of them
}