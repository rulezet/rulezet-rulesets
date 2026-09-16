rule TTP_XOR_QUAD_CurrentVersionRun_a1b7 {
  strings:
    $key_a1b7 = { f2 d8 [2] d6 d6 [2] fd fa [2] d3 d8 [2] c7 c3 [2] c8 d9 [2] d6 c4 [2] d4 c5 [2] cf c3 [2] d3 c4 [2] cf eb }

  condition:
    any of them
}