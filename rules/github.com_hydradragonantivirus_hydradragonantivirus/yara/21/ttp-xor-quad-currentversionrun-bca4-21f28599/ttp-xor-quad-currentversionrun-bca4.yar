rule TTP_XOR_QUAD_CurrentVersionRun_bca4 {
  strings:
    $key_bca4 = { ef cb [2] cb c5 [2] e0 e9 [2] ce cb [2] da d0 [2] d5 ca [2] cb d7 [2] c9 d6 [2] d2 d0 [2] ce d7 [2] d2 f8 }

  condition:
    any of them
}