rule TTP_XOR_QUAD_CurrentVersionRun_5db4 {
  strings:
    $key_5db4 = { 0e db [2] 2a d5 [2] 01 f9 [2] 2f db [2] 3b c0 [2] 34 da [2] 2a c7 [2] 28 c6 [2] 33 c0 [2] 2f c7 [2] 33 e8 }

  condition:
    any of them
}