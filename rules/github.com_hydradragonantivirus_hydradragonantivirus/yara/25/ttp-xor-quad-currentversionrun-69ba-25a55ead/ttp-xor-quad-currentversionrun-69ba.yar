rule TTP_XOR_QUAD_CurrentVersionRun_69ba {
  strings:
    $key_69ba = { 3a d5 [2] 1e db [2] 35 f7 [2] 1b d5 [2] 0f ce [2] 00 d4 [2] 1e c9 [2] 1c c8 [2] 07 ce [2] 1b c9 [2] 07 e6 }

  condition:
    any of them
}