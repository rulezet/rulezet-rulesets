rule TTP_XOR_QUAD_CurrentVersionRun_9d81 {
  strings:
    $key_9d81 = { ce ee [2] ea e0 [2] c1 cc [2] ef ee [2] fb f5 [2] f4 ef [2] ea f2 [2] e8 f3 [2] f3 f5 [2] ef f2 [2] f3 dd }

  condition:
    any of them
}