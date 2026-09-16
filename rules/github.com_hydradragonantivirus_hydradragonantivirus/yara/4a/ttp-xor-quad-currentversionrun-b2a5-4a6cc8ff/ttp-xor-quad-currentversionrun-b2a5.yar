rule TTP_XOR_QUAD_CurrentVersionRun_b2a5 {
  strings:
    $key_b2a5 = { e1 ca [2] c5 c4 [2] ee e8 [2] c0 ca [2] d4 d1 [2] db cb [2] c5 d6 [2] c7 d7 [2] dc d1 [2] c0 d6 [2] dc f9 }

  condition:
    any of them
}