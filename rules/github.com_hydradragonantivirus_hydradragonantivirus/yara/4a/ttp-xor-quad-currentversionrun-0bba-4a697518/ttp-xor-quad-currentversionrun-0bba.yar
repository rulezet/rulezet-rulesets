rule TTP_XOR_QUAD_CurrentVersionRun_0bba {
  strings:
    $key_0bba = { 58 d5 [2] 7c db [2] 57 f7 [2] 79 d5 [2] 6d ce [2] 62 d4 [2] 7c c9 [2] 7e c8 [2] 65 ce [2] 79 c9 [2] 65 e6 }

  condition:
    any of them
}