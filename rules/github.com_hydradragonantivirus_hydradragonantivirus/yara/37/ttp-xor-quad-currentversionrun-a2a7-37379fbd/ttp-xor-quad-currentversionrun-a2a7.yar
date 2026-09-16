rule TTP_XOR_QUAD_CurrentVersionRun_a2a7 {
  strings:
    $key_a2a7 = { f1 c8 [2] d5 c6 [2] fe ea [2] d0 c8 [2] c4 d3 [2] cb c9 [2] d5 d4 [2] d7 d5 [2] cc d3 [2] d0 d4 [2] cc fb }

  condition:
    any of them
}