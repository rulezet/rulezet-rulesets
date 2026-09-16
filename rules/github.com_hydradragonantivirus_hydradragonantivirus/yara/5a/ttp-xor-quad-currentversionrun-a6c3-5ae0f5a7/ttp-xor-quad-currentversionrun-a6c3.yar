rule TTP_XOR_QUAD_CurrentVersionRun_a6c3 {
  strings:
    $key_a6c3 = { f5 ac [2] d1 a2 [2] fa 8e [2] d4 ac [2] c0 b7 [2] cf ad [2] d1 b0 [2] d3 b1 [2] c8 b7 [2] d4 b0 [2] c8 9f }

  condition:
    any of them
}