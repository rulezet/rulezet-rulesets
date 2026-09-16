rule TTP_XOR_QUAD_CurrentVersionRun_bfa5 {
  strings:
    $key_bfa5 = { ec ca [2] c8 c4 [2] e3 e8 [2] cd ca [2] d9 d1 [2] d6 cb [2] c8 d6 [2] ca d7 [2] d1 d1 [2] cd d6 [2] d1 f9 }

  condition:
    any of them
}