rule TTP_XOR_QUAD_CurrentVersionRun_a5ba {
  strings:
    $key_a5ba = { f6 d5 [2] d2 db [2] f9 f7 [2] d7 d5 [2] c3 ce [2] cc d4 [2] d2 c9 [2] d0 c8 [2] cb ce [2] d7 c9 [2] cb e6 }

  condition:
    any of them
}