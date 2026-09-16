rule TTP_XOR_QUAD_CurrentVersionRun_48b4 {
  strings:
    $key_48b4 = { 1b db [2] 3f d5 [2] 14 f9 [2] 3a db [2] 2e c0 [2] 21 da [2] 3f c7 [2] 3d c6 [2] 26 c0 [2] 3a c7 [2] 26 e8 }

  condition:
    any of them
}