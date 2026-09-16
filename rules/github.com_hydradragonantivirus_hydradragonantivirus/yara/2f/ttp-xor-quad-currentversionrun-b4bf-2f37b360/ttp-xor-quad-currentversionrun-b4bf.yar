rule TTP_XOR_QUAD_CurrentVersionRun_b4bf {
  strings:
    $key_b4bf = { e7 d0 [2] c3 de [2] e8 f2 [2] c6 d0 [2] d2 cb [2] dd d1 [2] c3 cc [2] c1 cd [2] da cb [2] c6 cc [2] da e3 }

  condition:
    any of them
}