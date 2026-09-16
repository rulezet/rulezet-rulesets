rule TTP_XOR_QUAD_CurrentVersionRun_5bba {
  strings:
    $key_5bba = { 08 d5 [2] 2c db [2] 07 f7 [2] 29 d5 [2] 3d ce [2] 32 d4 [2] 2c c9 [2] 2e c8 [2] 35 ce [2] 29 c9 [2] 35 e6 }

  condition:
    any of them
}