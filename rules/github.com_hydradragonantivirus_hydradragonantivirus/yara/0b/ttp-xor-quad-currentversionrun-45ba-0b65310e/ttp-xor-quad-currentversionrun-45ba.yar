rule TTP_XOR_QUAD_CurrentVersionRun_45ba {
  strings:
    $key_45ba = { 16 d5 [2] 32 db [2] 19 f7 [2] 37 d5 [2] 23 ce [2] 2c d4 [2] 32 c9 [2] 30 c8 [2] 2b ce [2] 37 c9 [2] 2b e6 }

  condition:
    any of them
}