rule TTP_XOR_QUAD_CurrentVersionRun_70aa {
  strings:
    $key_70aa = { 23 c5 [2] 07 cb [2] 2c e7 [2] 02 c5 [2] 16 de [2] 19 c4 [2] 07 d9 [2] 05 d8 [2] 1e de [2] 02 d9 [2] 1e f6 }

  condition:
    any of them
}