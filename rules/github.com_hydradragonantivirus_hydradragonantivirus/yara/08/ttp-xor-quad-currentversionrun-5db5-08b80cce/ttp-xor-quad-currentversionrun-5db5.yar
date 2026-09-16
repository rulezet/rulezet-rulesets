rule TTP_XOR_QUAD_CurrentVersionRun_5db5 {
  strings:
    $key_5db5 = { 0e da [2] 2a d4 [2] 01 f8 [2] 2f da [2] 3b c1 [2] 34 db [2] 2a c6 [2] 28 c7 [2] 33 c1 [2] 2f c6 [2] 33 e9 }

  condition:
    any of them
}