rule TTP_XOR_QUAD_CurrentVersionRun_02ba {
  strings:
    $key_02ba = { 51 d5 [2] 75 db [2] 5e f7 [2] 70 d5 [2] 64 ce [2] 6b d4 [2] 75 c9 [2] 77 c8 [2] 6c ce [2] 70 c9 [2] 6c e6 }

  condition:
    any of them
}