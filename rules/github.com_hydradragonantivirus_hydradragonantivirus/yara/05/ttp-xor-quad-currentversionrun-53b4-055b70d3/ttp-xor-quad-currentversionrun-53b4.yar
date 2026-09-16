rule TTP_XOR_QUAD_CurrentVersionRun_53b4 {
  strings:
    $key_53b4 = { 00 db [2] 24 d5 [2] 0f f9 [2] 21 db [2] 35 c0 [2] 3a da [2] 24 c7 [2] 26 c6 [2] 3d c0 [2] 21 c7 [2] 3d e8 }

  condition:
    any of them
}