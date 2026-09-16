rule TTP_XOR_QUAD_CurrentVersionRun_a6a4 {
  strings:
    $key_a6a4 = { f5 cb [2] d1 c5 [2] fa e9 [2] d4 cb [2] c0 d0 [2] cf ca [2] d1 d7 [2] d3 d6 [2] c8 d0 [2] d4 d7 [2] c8 f8 }

  condition:
    any of them
}