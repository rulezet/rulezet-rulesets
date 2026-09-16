rule TTP_XOR_QUAD_CurrentVersionRun_9a95 {
  strings:
    $key_9a95 = { c9 fa [2] ed f4 [2] c6 d8 [2] e8 fa [2] fc e1 [2] f3 fb [2] ed e6 [2] ef e7 [2] f4 e1 [2] e8 e6 [2] f4 c9 }

  condition:
    any of them
}