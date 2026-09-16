rule TTP_XOR_QUAD_CurrentVersionRun_5dba {
  strings:
    $key_5dba = { 0e d5 [2] 2a db [2] 01 f7 [2] 2f d5 [2] 3b ce [2] 34 d4 [2] 2a c9 [2] 28 c8 [2] 33 ce [2] 2f c9 [2] 33 e6 }

  condition:
    any of them
}