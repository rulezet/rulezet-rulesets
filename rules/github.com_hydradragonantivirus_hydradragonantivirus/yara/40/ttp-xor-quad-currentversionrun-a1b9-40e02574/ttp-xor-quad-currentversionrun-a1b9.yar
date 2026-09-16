rule TTP_XOR_QUAD_CurrentVersionRun_a1b9 {
  strings:
    $key_a1b9 = { f2 d6 [2] d6 d8 [2] fd f4 [2] d3 d6 [2] c7 cd [2] c8 d7 [2] d6 ca [2] d4 cb [2] cf cd [2] d3 ca [2] cf e5 }

  condition:
    any of them
}