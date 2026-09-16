rule TTP_XOR_QUAD_CurrentVersionRun_3ea8 {
  strings:
    $key_3ea8 = { 6d c7 [2] 49 c9 [2] 62 e5 [2] 4c c7 [2] 58 dc [2] 57 c6 [2] 49 db [2] 4b da [2] 50 dc [2] 4c db [2] 50 f4 }

  condition:
    any of them
}