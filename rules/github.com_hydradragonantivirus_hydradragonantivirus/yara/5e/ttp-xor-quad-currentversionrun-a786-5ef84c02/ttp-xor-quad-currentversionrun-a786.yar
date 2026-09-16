rule TTP_XOR_QUAD_CurrentVersionRun_a786 {
  strings:
    $key_a786 = { f4 e9 [2] d0 e7 [2] fb cb [2] d5 e9 [2] c1 f2 [2] ce e8 [2] d0 f5 [2] d2 f4 [2] c9 f2 [2] d5 f5 [2] c9 da }

  condition:
    any of them
}