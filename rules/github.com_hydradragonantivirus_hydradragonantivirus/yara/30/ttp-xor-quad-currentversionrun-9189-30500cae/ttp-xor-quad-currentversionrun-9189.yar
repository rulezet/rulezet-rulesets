rule TTP_XOR_QUAD_CurrentVersionRun_9189 {
  strings:
    $key_9189 = { c2 e6 [2] e6 e8 [2] cd c4 [2] e3 e6 [2] f7 fd [2] f8 e7 [2] e6 fa [2] e4 fb [2] ff fd [2] e3 fa [2] ff d5 }

  condition:
    any of them
}