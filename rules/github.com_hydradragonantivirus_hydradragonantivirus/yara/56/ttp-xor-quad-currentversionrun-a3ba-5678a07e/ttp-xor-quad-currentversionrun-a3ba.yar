rule TTP_XOR_QUAD_CurrentVersionRun_a3ba {
  strings:
    $key_a3ba = { f0 d5 [2] d4 db [2] ff f7 [2] d1 d5 [2] c5 ce [2] ca d4 [2] d4 c9 [2] d6 c8 [2] cd ce [2] d1 c9 [2] cd e6 }

  condition:
    any of them
}