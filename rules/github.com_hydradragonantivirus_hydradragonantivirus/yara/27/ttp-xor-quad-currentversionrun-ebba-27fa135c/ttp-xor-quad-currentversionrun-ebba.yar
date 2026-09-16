rule TTP_XOR_QUAD_CurrentVersionRun_ebba {
  strings:
    $key_ebba = { b8 d5 [2] 9c db [2] b7 f7 [2] 99 d5 [2] 8d ce [2] 82 d4 [2] 9c c9 [2] 9e c8 [2] 85 ce [2] 99 c9 [2] 85 e6 }

  condition:
    any of them
}