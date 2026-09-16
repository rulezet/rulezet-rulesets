rule TTP_XOR_QUAD_CurrentVersionRun_54b5 {
  strings:
    $key_54b5 = { 07 da [2] 23 d4 [2] 08 f8 [2] 26 da [2] 32 c1 [2] 3d db [2] 23 c6 [2] 21 c7 [2] 3a c1 [2] 26 c6 [2] 3a e9 }

  condition:
    any of them
}