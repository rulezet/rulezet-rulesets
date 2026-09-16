rule TTP_XOR_QUAD_CurrentVersionRun_3eb4 {
  strings:
    $key_3eb4 = { 6d db [2] 49 d5 [2] 62 f9 [2] 4c db [2] 58 c0 [2] 57 da [2] 49 c7 [2] 4b c6 [2] 50 c0 [2] 4c c7 [2] 50 e8 }

  condition:
    any of them
}