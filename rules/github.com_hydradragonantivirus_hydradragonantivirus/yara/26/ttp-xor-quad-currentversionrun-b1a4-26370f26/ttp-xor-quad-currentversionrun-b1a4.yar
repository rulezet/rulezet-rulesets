rule TTP_XOR_QUAD_CurrentVersionRun_b1a4 {
  strings:
    $key_b1a4 = { e2 cb [2] c6 c5 [2] ed e9 [2] c3 cb [2] d7 d0 [2] d8 ca [2] c6 d7 [2] c4 d6 [2] df d0 [2] c3 d7 [2] df f8 }

  condition:
    any of them
}