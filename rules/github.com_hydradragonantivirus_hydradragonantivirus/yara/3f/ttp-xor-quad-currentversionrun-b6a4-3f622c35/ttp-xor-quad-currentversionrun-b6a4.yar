rule TTP_XOR_QUAD_CurrentVersionRun_b6a4 {
  strings:
    $key_b6a4 = { e5 cb [2] c1 c5 [2] ea e9 [2] c4 cb [2] d0 d0 [2] df ca [2] c1 d7 [2] c3 d6 [2] d8 d0 [2] c4 d7 [2] d8 f8 }

  condition:
    any of them
}