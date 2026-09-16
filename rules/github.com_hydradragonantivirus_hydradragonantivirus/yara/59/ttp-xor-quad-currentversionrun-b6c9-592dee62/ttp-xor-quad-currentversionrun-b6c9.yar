rule TTP_XOR_QUAD_CurrentVersionRun_b6c9 {
  strings:
    $key_b6c9 = { e5 a6 [2] c1 a8 [2] ea 84 [2] c4 a6 [2] d0 bd [2] df a7 [2] c1 ba [2] c3 bb [2] d8 bd [2] c4 ba [2] d8 95 }

  condition:
    any of them
}