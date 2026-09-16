rule TTP_XOR_QUAD_CurrentVersionRun_a7a4 {
  strings:
    $key_a7a4 = { f4 cb [2] d0 c5 [2] fb e9 [2] d5 cb [2] c1 d0 [2] ce ca [2] d0 d7 [2] d2 d6 [2] c9 d0 [2] d5 d7 [2] c9 f8 }

  condition:
    any of them
}