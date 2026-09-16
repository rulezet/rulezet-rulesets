rule TTP_XOR_QUAD_CurrentVersionRun_bca5 {
  strings:
    $key_bca5 = { ef ca [2] cb c4 [2] e0 e8 [2] ce ca [2] da d1 [2] d5 cb [2] cb d6 [2] c9 d7 [2] d2 d1 [2] ce d6 [2] d2 f9 }

  condition:
    any of them
}