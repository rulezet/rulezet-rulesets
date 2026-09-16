rule TTP_XOR_QUAD_CurrentVersionRun_9a88 {
  strings:
    $key_9a88 = { c9 e7 [2] ed e9 [2] c6 c5 [2] e8 e7 [2] fc fc [2] f3 e6 [2] ed fb [2] ef fa [2] f4 fc [2] e8 fb [2] f4 d4 }

  condition:
    any of them
}