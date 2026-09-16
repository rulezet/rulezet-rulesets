rule TTP_XOR_QUAD_CurrentVersionRun_a1c3 {
  strings:
    $key_a1c3 = { f2 ac [2] d6 a2 [2] fd 8e [2] d3 ac [2] c7 b7 [2] c8 ad [2] d6 b0 [2] d4 b1 [2] cf b7 [2] d3 b0 [2] cf 9f }

  condition:
    any of them
}