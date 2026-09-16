rule TTP_XOR_QUAD_CurrentVersionRun_a3b4 {
  strings:
    $key_a3b4 = { f0 db [2] d4 d5 [2] ff f9 [2] d1 db [2] c5 c0 [2] ca da [2] d4 c7 [2] d6 c6 [2] cd c0 [2] d1 c7 [2] cd e8 }

  condition:
    any of them
}