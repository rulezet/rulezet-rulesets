rule TTP_XOR_QUAD_CurrentVersionRun_2dba {
  strings:
    $key_2dba = { 7e d5 [2] 5a db [2] 71 f7 [2] 5f d5 [2] 4b ce [2] 44 d4 [2] 5a c9 [2] 58 c8 [2] 43 ce [2] 5f c9 [2] 43 e6 }

  condition:
    any of them
}