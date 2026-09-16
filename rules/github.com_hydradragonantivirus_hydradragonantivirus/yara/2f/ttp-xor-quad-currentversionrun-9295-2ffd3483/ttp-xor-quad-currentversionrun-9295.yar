rule TTP_XOR_QUAD_CurrentVersionRun_9295 {
  strings:
    $key_9295 = { c1 fa [2] e5 f4 [2] ce d8 [2] e0 fa [2] f4 e1 [2] fb fb [2] e5 e6 [2] e7 e7 [2] fc e1 [2] e0 e6 [2] fc c9 }

  condition:
    any of them
}