rule TTP_XOR_QUAD_CurrentVersionRun_1eb4 {
  strings:
    $key_1eb4 = { 4d db [2] 69 d5 [2] 42 f9 [2] 6c db [2] 78 c0 [2] 77 da [2] 69 c7 [2] 6b c6 [2] 70 c0 [2] 6c c7 [2] 70 e8 }

  condition:
    any of them
}