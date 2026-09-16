rule TTP_XOR_QUAD_CurrentVersionRun_bfb4 {
  strings:
    $key_bfb4 = { ec db [2] c8 d5 [2] e3 f9 [2] cd db [2] d9 c0 [2] d6 da [2] c8 c7 [2] ca c6 [2] d1 c0 [2] cd c7 [2] d1 e8 }

  condition:
    any of them
}