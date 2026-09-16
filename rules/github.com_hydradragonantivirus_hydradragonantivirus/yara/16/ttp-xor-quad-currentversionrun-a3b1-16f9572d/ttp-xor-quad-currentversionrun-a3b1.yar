rule TTP_XOR_QUAD_CurrentVersionRun_a3b1 {
  strings:
    $key_a3b1 = { f0 de [2] d4 d0 [2] ff fc [2] d1 de [2] c5 c5 [2] ca df [2] d4 c2 [2] d6 c3 [2] cd c5 [2] d1 c2 [2] cd ed }

  condition:
    any of them
}