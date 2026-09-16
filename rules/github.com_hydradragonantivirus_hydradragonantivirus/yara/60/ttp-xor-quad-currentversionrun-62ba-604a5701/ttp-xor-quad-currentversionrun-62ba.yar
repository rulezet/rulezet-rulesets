rule TTP_XOR_QUAD_CurrentVersionRun_62ba {
  strings:
    $key_62ba = { 31 d5 [2] 15 db [2] 3e f7 [2] 10 d5 [2] 04 ce [2] 0b d4 [2] 15 c9 [2] 17 c8 [2] 0c ce [2] 10 c9 [2] 0c e6 }

  condition:
    any of them
}