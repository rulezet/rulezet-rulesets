rule TTP_XOR_QUAD_CurrentVersionRun_9395 {
  strings:
    $key_9395 = { c0 fa [2] e4 f4 [2] cf d8 [2] e1 fa [2] f5 e1 [2] fa fb [2] e4 e6 [2] e6 e7 [2] fd e1 [2] e1 e6 [2] fd c9 }

  condition:
    any of them
}