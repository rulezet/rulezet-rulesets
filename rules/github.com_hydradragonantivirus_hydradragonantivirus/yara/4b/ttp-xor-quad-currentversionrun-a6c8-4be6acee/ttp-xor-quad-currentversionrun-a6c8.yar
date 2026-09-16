rule TTP_XOR_QUAD_CurrentVersionRun_a6c8 {
  strings:
    $key_a6c8 = { f5 a7 [2] d1 a9 [2] fa 85 [2] d4 a7 [2] c0 bc [2] cf a6 [2] d1 bb [2] d3 ba [2] c8 bc [2] d4 bb [2] c8 94 }

  condition:
    any of them
}