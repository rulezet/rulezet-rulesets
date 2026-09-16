rule TTP_XOR_QUAD_CurrentVersionRun_b2aa {
  strings:
    $key_b2aa = { e1 c5 [2] c5 cb [2] ee e7 [2] c0 c5 [2] d4 de [2] db c4 [2] c5 d9 [2] c7 d8 [2] dc de [2] c0 d9 [2] dc f6 }

  condition:
    any of them
}