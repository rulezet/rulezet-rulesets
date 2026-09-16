rule TTP_XOR_QUAD_CurrentVersionRun_04b5 {
  strings:
    $key_04b5 = { 57 da [2] 73 d4 [2] 58 f8 [2] 76 da [2] 62 c1 [2] 6d db [2] 73 c6 [2] 71 c7 [2] 6a c1 [2] 76 c6 [2] 6a e9 }

  condition:
    any of them
}