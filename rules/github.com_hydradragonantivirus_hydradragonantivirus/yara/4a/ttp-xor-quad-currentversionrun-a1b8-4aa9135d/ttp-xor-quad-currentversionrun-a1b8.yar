rule TTP_XOR_QUAD_CurrentVersionRun_a1b8 {
  strings:
    $key_a1b8 = { f2 d7 [2] d6 d9 [2] fd f5 [2] d3 d7 [2] c7 cc [2] c8 d6 [2] d6 cb [2] d4 ca [2] cf cc [2] d3 cb [2] cf e4 }

  condition:
    any of them
}