rule TTP_XOR_QUAD_CurrentVersionRun_a6a6 {
  strings:
    $key_a6a6 = { f5 c9 [2] d1 c7 [2] fa eb [2] d4 c9 [2] c0 d2 [2] cf c8 [2] d1 d5 [2] d3 d4 [2] c8 d2 [2] d4 d5 [2] c8 fa }

  condition:
    any of them
}