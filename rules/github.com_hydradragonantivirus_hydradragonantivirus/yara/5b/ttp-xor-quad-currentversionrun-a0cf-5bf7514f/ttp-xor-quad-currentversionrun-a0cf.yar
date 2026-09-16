rule TTP_XOR_QUAD_CurrentVersionRun_a0cf {
  strings:
    $key_a0cf = { f3 a0 [2] d7 ae [2] fc 82 [2] d2 a0 [2] c6 bb [2] c9 a1 [2] d7 bc [2] d5 bd [2] ce bb [2] d2 bc [2] ce 93 }

  condition:
    any of them
}