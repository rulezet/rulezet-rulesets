rule TTP_XOR_QUAD_CurrentVersionRun_a3b5 {
  strings:
    $key_a3b5 = { f0 da [2] d4 d4 [2] ff f8 [2] d1 da [2] c5 c1 [2] ca db [2] d4 c6 [2] d6 c7 [2] cd c1 [2] d1 c6 [2] cd e9 }

  condition:
    any of them
}