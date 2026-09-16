rule TTP_XOR_QUAD_CurrentVersionRun_9588 {
  strings:
    $key_9588 = { c6 e7 [2] e2 e9 [2] c9 c5 [2] e7 e7 [2] f3 fc [2] fc e6 [2] e2 fb [2] e0 fa [2] fb fc [2] e7 fb [2] fb d4 }

  condition:
    any of them
}