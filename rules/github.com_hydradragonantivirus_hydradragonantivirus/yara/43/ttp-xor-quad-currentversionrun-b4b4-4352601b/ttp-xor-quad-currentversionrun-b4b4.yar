rule TTP_XOR_QUAD_CurrentVersionRun_b4b4 {
  strings:
    $key_b4b4 = { e7 db [2] c3 d5 [2] e8 f9 [2] c6 db [2] d2 c0 [2] dd da [2] c3 c7 [2] c1 c6 [2] da c0 [2] c6 c7 [2] da e8 }

  condition:
    any of them
}