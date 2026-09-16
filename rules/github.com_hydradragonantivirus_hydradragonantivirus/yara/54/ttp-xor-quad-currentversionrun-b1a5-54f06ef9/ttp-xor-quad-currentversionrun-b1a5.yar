rule TTP_XOR_QUAD_CurrentVersionRun_b1a5 {
  strings:
    $key_b1a5 = { e2 ca [2] c6 c4 [2] ed e8 [2] c3 ca [2] d7 d1 [2] d8 cb [2] c6 d6 [2] c4 d7 [2] df d1 [2] c3 d6 [2] df f9 }

  condition:
    any of them
}