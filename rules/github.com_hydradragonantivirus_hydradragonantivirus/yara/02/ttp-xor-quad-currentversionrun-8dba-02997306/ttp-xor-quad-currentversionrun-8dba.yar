rule TTP_XOR_QUAD_CurrentVersionRun_8dba {
  strings:
    $key_8dba = { de d5 [2] fa db [2] d1 f7 [2] ff d5 [2] eb ce [2] e4 d4 [2] fa c9 [2] f8 c8 [2] e3 ce [2] ff c9 [2] e3 e6 }

  condition:
    any of them
}