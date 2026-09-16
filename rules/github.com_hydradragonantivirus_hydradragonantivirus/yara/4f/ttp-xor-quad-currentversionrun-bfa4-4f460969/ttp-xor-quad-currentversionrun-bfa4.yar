rule TTP_XOR_QUAD_CurrentVersionRun_bfa4 {
  strings:
    $key_bfa4 = { ec cb [2] c8 c5 [2] e3 e9 [2] cd cb [2] d9 d0 [2] d6 ca [2] c8 d7 [2] ca d6 [2] d1 d0 [2] cd d7 [2] d1 f8 }

  condition:
    any of them
}