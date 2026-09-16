rule TTP_XOR_QUAD_CurrentVersionRun_9dae {
  strings:
    $key_9dae = { ce c1 [2] ea cf [2] c1 e3 [2] ef c1 [2] fb da [2] f4 c0 [2] ea dd [2] e8 dc [2] f3 da [2] ef dd [2] f3 f2 }

  condition:
    any of them
}