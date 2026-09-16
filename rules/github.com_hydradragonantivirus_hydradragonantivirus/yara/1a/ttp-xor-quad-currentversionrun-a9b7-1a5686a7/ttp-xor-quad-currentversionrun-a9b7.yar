rule TTP_XOR_QUAD_CurrentVersionRun_a9b7 {
  strings:
    $key_a9b7 = { fa d8 [2] de d6 [2] f5 fa [2] db d8 [2] cf c3 [2] c0 d9 [2] de c4 [2] dc c5 [2] c7 c3 [2] db c4 [2] c7 eb }

  condition:
    any of them
}