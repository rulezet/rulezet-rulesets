rule TTP_XOR_QUAD_CurrentVersionRun_b8b5 {
  strings:
    $key_b8b5 = { eb da [2] cf d4 [2] e4 f8 [2] ca da [2] de c1 [2] d1 db [2] cf c6 [2] cd c7 [2] d6 c1 [2] ca c6 [2] d6 e9 }

  condition:
    any of them
}