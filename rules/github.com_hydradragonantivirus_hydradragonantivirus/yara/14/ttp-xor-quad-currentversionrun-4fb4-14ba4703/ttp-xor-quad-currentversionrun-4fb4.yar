rule TTP_XOR_QUAD_CurrentVersionRun_4fb4 {
  strings:
    $key_4fb4 = { 1c db [2] 38 d5 [2] 13 f9 [2] 3d db [2] 29 c0 [2] 26 da [2] 38 c7 [2] 3a c6 [2] 21 c0 [2] 3d c7 [2] 21 e8 }

  condition:
    any of them
}