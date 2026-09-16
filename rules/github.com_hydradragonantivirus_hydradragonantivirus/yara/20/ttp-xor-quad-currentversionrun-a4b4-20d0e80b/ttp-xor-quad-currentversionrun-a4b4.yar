rule TTP_XOR_QUAD_CurrentVersionRun_a4b4 {
  strings:
    $key_a4b4 = { f7 db [2] d3 d5 [2] f8 f9 [2] d6 db [2] c2 c0 [2] cd da [2] d3 c7 [2] d1 c6 [2] ca c0 [2] d6 c7 [2] ca e8 }

  condition:
    any of them
}