rule TTP_XOR_QUAD_CurrentVersionRun_a7aa {
  strings:
    $key_a7aa = { f4 c5 [2] d0 cb [2] fb e7 [2] d5 c5 [2] c1 de [2] ce c4 [2] d0 d9 [2] d2 d8 [2] c9 de [2] d5 d9 [2] c9 f6 }

  condition:
    any of them
}