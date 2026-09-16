rule TTP_XOR_QUAD_CurrentVersionRun_4cba {
  strings:
    $key_4cba = { 1f d5 [2] 3b db [2] 10 f7 [2] 3e d5 [2] 2a ce [2] 25 d4 [2] 3b c9 [2] 39 c8 [2] 22 ce [2] 3e c9 [2] 22 e6 }

  condition:
    any of them
}