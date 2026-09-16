rule TTP_XOR_QUAD_CurrentVersionRun_aba4 {
  strings:
    $key_aba4 = { f8 cb [2] dc c5 [2] f7 e9 [2] d9 cb [2] cd d0 [2] c2 ca [2] dc d7 [2] de d6 [2] c5 d0 [2] d9 d7 [2] c5 f8 }

  condition:
    any of them
}