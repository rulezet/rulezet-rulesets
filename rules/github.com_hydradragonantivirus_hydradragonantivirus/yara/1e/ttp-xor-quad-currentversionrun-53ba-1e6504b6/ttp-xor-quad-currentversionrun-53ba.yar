rule TTP_XOR_QUAD_CurrentVersionRun_53ba {
  strings:
    $key_53ba = { 00 d5 [2] 24 db [2] 0f f7 [2] 21 d5 [2] 35 ce [2] 3a d4 [2] 24 c9 [2] 26 c8 [2] 3d ce [2] 21 c9 [2] 3d e6 }

  condition:
    any of them
}