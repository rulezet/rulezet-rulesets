rule TTP_XOR_QUAD_CurrentVersionRun_a7c8 {
  strings:
    $key_a7c8 = { f4 a7 [2] d0 a9 [2] fb 85 [2] d5 a7 [2] c1 bc [2] ce a6 [2] d0 bb [2] d2 ba [2] c9 bc [2] d5 bb [2] c9 94 }

  condition:
    any of them
}