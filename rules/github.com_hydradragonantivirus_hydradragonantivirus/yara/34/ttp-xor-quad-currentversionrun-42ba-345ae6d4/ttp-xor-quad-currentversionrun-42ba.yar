rule TTP_XOR_QUAD_CurrentVersionRun_42ba {
  strings:
    $key_42ba = { 11 d5 [2] 35 db [2] 1e f7 [2] 30 d5 [2] 24 ce [2] 2b d4 [2] 35 c9 [2] 37 c8 [2] 2c ce [2] 30 c9 [2] 2c e6 }

  condition:
    any of them
}