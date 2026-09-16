rule TTP_XOR_QUAD_CurrentVersionRun_beb7 {
  strings:
    $key_beb7 = { ed d8 [2] c9 d6 [2] e2 fa [2] cc d8 [2] d8 c3 [2] d7 d9 [2] c9 c4 [2] cb c5 [2] d0 c3 [2] cc c4 [2] d0 eb }

  condition:
    any of them
}