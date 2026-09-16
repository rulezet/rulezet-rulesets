rule TTP_XOR_QUAD_CurrentVersionRun_7dba {
  strings:
    $key_7dba = { 2e d5 [2] 0a db [2] 21 f7 [2] 0f d5 [2] 1b ce [2] 14 d4 [2] 0a c9 [2] 08 c8 [2] 13 ce [2] 0f c9 [2] 13 e6 }

  condition:
    any of them
}