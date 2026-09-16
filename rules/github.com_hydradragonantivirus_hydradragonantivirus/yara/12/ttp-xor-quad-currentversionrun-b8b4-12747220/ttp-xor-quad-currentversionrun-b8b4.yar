rule TTP_XOR_QUAD_CurrentVersionRun_b8b4 {
  strings:
    $key_b8b4 = { eb db [2] cf d5 [2] e4 f9 [2] ca db [2] de c0 [2] d1 da [2] cf c7 [2] cd c6 [2] d6 c0 [2] ca c7 [2] d6 e8 }

  condition:
    any of them
}