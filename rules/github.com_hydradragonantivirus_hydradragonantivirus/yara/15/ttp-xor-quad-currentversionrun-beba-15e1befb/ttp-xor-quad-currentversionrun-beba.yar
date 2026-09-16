rule TTP_XOR_QUAD_CurrentVersionRun_beba {
  strings:
    $key_beba = { ed d5 [2] c9 db [2] e2 f7 [2] cc d5 [2] d8 ce [2] d7 d4 [2] c9 c9 [2] cb c8 [2] d0 ce [2] cc c9 [2] d0 e6 }

  condition:
    any of them
}