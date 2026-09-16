rule TTP_XOR_QUAD_CurrentVersionRun_b4ba {
  strings:
    $key_b4ba = { e7 d5 [2] c3 db [2] e8 f7 [2] c6 d5 [2] d2 ce [2] dd d4 [2] c3 c9 [2] c1 c8 [2] da ce [2] c6 c9 [2] da e6 }

  condition:
    any of them
}