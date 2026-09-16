rule TTP_XOR_QUAD_CurrentVersionRun_53b5 {
  strings:
    $key_53b5 = { 00 da [2] 24 d4 [2] 0f f8 [2] 21 da [2] 35 c1 [2] 3a db [2] 24 c6 [2] 26 c7 [2] 3d c1 [2] 21 c6 [2] 3d e9 }

  condition:
    any of them
}