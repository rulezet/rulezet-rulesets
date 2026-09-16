rule TTP_XOR_QUAD_CurrentVersionRun_1ea8 {
  strings:
    $key_1ea8 = { 4d c7 [2] 69 c9 [2] 42 e5 [2] 6c c7 [2] 78 dc [2] 77 c6 [2] 69 db [2] 6b da [2] 70 dc [2] 6c db [2] 70 f4 }

  condition:
    any of them
}