rule TTP_XOR_QUAD_CurrentVersionRun_9581 {
  strings:
    $key_9581 = { c6 ee [2] e2 e0 [2] c9 cc [2] e7 ee [2] f3 f5 [2] fc ef [2] e2 f2 [2] e0 f3 [2] fb f5 [2] e7 f2 [2] fb dd }

  condition:
    any of them
}