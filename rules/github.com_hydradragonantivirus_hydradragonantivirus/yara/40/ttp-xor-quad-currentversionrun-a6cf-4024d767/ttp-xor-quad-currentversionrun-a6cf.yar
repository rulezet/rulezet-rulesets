rule TTP_XOR_QUAD_CurrentVersionRun_a6cf {
  strings:
    $key_a6cf = { f5 a0 [2] d1 ae [2] fa 82 [2] d4 a0 [2] c0 bb [2] cf a1 [2] d1 bc [2] d3 bd [2] c8 bb [2] d4 bc [2] c8 93 }

  condition:
    any of them
}