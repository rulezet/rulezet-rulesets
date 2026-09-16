rule TTP_XOR_QUAD_CurrentVersionRun_a3a5 {
  strings:
    $key_a3a5 = { f0 ca [2] d4 c4 [2] ff e8 [2] d1 ca [2] c5 d1 [2] ca cb [2] d4 d6 [2] d6 d7 [2] cd d1 [2] d1 d6 [2] cd f9 }

  condition:
    any of them
}