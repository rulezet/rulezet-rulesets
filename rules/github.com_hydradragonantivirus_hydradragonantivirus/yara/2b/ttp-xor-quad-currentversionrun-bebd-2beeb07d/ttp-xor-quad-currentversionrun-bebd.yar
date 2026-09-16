rule TTP_XOR_QUAD_CurrentVersionRun_bebd {
  strings:
    $key_bebd = { ed d2 [2] c9 dc [2] e2 f0 [2] cc d2 [2] d8 c9 [2] d7 d3 [2] c9 ce [2] cb cf [2] d0 c9 [2] cc ce [2] d0 e1 }

  condition:
    any of them
}