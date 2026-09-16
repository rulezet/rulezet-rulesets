rule TTP_XOR_QUAD_CurrentVersionRun_9094 {
  strings:
    $key_9094 = { c3 fb [2] e7 f5 [2] cc d9 [2] e2 fb [2] f6 e0 [2] f9 fa [2] e7 e7 [2] e5 e6 [2] fe e0 [2] e2 e7 [2] fe c8 }

  condition:
    any of them
}