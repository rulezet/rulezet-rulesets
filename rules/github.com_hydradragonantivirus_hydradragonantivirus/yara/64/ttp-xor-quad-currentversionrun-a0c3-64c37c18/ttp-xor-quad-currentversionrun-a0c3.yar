rule TTP_XOR_QUAD_CurrentVersionRun_a0c3 {
  strings:
    $key_a0c3 = { f3 ac [2] d7 a2 [2] fc 8e [2] d2 ac [2] c6 b7 [2] c9 ad [2] d7 b0 [2] d5 b1 [2] ce b7 [2] d2 b0 [2] ce 9f }

  condition:
    any of them
}