rule TTP_XOR_QUAD_CurrentVersionRun_a6a5 {
  strings:
    $key_a6a5 = { f5 ca [2] d1 c4 [2] fa e8 [2] d4 ca [2] c0 d1 [2] cf cb [2] d1 d6 [2] d3 d7 [2] c8 d1 [2] d4 d6 [2] c8 f9 }

  condition:
    any of them
}