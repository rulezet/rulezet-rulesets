rule TTP_XOR_QUAD_CurrentVersionRun_beb8 {
  strings:
    $key_beb8 = { ed d7 [2] c9 d9 [2] e2 f5 [2] cc d7 [2] d8 cc [2] d7 d6 [2] c9 cb [2] cb ca [2] d0 cc [2] cc cb [2] d0 e4 }

  condition:
    any of them
}