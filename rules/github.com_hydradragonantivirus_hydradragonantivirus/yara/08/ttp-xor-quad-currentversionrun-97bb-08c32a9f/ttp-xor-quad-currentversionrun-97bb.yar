rule TTP_XOR_QUAD_CurrentVersionRun_97bb {
  strings:
    $key_97bb = { c4 d4 [2] e0 da [2] cb f6 [2] e5 d4 [2] f1 cf [2] fe d5 [2] e0 c8 [2] e2 c9 [2] f9 cf [2] e5 c8 [2] f9 e7 }

  condition:
    any of them
}