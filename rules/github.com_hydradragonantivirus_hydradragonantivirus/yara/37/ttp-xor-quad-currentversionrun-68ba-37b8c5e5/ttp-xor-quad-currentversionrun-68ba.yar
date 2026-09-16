rule TTP_XOR_QUAD_CurrentVersionRun_68ba {
  strings:
    $key_68ba = { 3b d5 [2] 1f db [2] 34 f7 [2] 1a d5 [2] 0e ce [2] 01 d4 [2] 1f c9 [2] 1d c8 [2] 06 ce [2] 1a c9 [2] 06 e6 }

  condition:
    any of them
}