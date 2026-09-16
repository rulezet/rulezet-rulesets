rule TTP_XOR_QUAD_CurrentVersionRun_72ba {
  strings:
    $key_72ba = { 21 d5 [2] 05 db [2] 2e f7 [2] 00 d5 [2] 14 ce [2] 1b d4 [2] 05 c9 [2] 07 c8 [2] 1c ce [2] 00 c9 [2] 1c e6 }

  condition:
    any of them
}