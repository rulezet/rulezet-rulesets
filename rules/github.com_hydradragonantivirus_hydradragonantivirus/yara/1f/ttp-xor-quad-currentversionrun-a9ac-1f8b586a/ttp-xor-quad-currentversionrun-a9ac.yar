rule TTP_XOR_QUAD_CurrentVersionRun_a9ac {
  strings:
    $key_a9ac = { fa c3 [2] de cd [2] f5 e1 [2] db c3 [2] cf d8 [2] c0 c2 [2] de df [2] dc de [2] c7 d8 [2] db df [2] c7 f0 }

  condition:
    any of them
}