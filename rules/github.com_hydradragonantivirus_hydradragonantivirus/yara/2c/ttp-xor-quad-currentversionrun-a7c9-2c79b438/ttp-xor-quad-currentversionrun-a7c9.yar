rule TTP_XOR_QUAD_CurrentVersionRun_a7c9 {
  strings:
    $key_a7c9 = { f4 a6 [2] d0 a8 [2] fb 84 [2] d5 a6 [2] c1 bd [2] ce a7 [2] d0 ba [2] d2 bb [2] c9 bd [2] d5 ba [2] c9 95 }

  condition:
    any of them
}