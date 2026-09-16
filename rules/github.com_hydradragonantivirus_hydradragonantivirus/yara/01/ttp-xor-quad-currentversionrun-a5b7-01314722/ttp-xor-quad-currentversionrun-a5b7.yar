rule TTP_XOR_QUAD_CurrentVersionRun_a5b7 {
  strings:
    $key_a5b7 = { f6 d8 [2] d2 d6 [2] f9 fa [2] d7 d8 [2] c3 c3 [2] cc d9 [2] d2 c4 [2] d0 c5 [2] cb c3 [2] d7 c4 [2] cb eb }

  condition:
    any of them
}