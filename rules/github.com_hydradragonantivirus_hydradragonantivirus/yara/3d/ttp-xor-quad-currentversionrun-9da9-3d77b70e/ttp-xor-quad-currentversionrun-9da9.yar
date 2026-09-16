rule TTP_XOR_QUAD_CurrentVersionRun_9da9 {
  strings:
    $key_9da9 = { ce c6 [2] ea c8 [2] c1 e4 [2] ef c6 [2] fb dd [2] f4 c7 [2] ea da [2] e8 db [2] f3 dd [2] ef da [2] f3 f5 }

  condition:
    any of them
}