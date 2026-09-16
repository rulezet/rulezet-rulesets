rule TTP_XOR_QUAD_CurrentVersionRun_a3b8 {
  strings:
    $key_a3b8 = { f0 d7 [2] d4 d9 [2] ff f5 [2] d1 d7 [2] c5 cc [2] ca d6 [2] d4 cb [2] d6 ca [2] cd cc [2] d1 cb [2] cd e4 }

  condition:
    any of them
}