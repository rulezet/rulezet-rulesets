rule TTP_XOR_QUAD_CurrentVersionRun_a7c3 {
  strings:
    $key_a7c3 = { f4 ac [2] d0 a2 [2] fb 8e [2] d5 ac [2] c1 b7 [2] ce ad [2] d0 b0 [2] d2 b1 [2] c9 b7 [2] d5 b0 [2] c9 9f }

  condition:
    any of them
}