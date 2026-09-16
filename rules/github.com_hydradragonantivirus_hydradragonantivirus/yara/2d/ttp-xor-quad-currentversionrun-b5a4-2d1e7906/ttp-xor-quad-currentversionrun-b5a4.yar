rule TTP_XOR_QUAD_CurrentVersionRun_b5a4 {
  strings:
    $key_b5a4 = { e6 cb [2] c2 c5 [2] e9 e9 [2] c7 cb [2] d3 d0 [2] dc ca [2] c2 d7 [2] c0 d6 [2] db d0 [2] c7 d7 [2] db f8 }

  condition:
    any of them
}