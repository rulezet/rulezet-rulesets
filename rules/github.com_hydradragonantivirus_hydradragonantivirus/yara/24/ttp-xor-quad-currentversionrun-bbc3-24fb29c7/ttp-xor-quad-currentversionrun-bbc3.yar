rule TTP_XOR_QUAD_CurrentVersionRun_bbc3 {
  strings:
    $key_bbc3 = { e8 ac [2] cc a2 [2] e7 8e [2] c9 ac [2] dd b7 [2] d2 ad [2] cc b0 [2] ce b1 [2] d5 b7 [2] c9 b0 [2] d5 9f }

  condition:
    any of them
}