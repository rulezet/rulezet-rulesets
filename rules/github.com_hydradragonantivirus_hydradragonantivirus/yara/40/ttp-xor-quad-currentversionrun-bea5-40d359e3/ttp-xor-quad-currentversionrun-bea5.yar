rule TTP_XOR_QUAD_CurrentVersionRun_bea5 {
  strings:
    $key_bea5 = { ed ca [2] c9 c4 [2] e2 e8 [2] cc ca [2] d8 d1 [2] d7 cb [2] c9 d6 [2] cb d7 [2] d0 d1 [2] cc d6 [2] d0 f9 }

  condition:
    any of them
}