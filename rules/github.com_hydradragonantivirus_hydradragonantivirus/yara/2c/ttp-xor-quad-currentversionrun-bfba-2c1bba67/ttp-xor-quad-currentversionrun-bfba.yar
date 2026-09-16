rule TTP_XOR_QUAD_CurrentVersionRun_bfba {
  strings:
    $key_bfba = { ec d5 [2] c8 db [2] e3 f7 [2] cd d5 [2] d9 ce [2] d6 d4 [2] c8 c9 [2] ca c8 [2] d1 ce [2] cd c9 [2] d1 e6 }

  condition:
    any of them
}