rule TTP_XOR_QUAD_CurrentVersionRun_9195 {
  strings:
    $key_9195 = { c2 fa [2] e6 f4 [2] cd d8 [2] e3 fa [2] f7 e1 [2] f8 fb [2] e6 e6 [2] e4 e7 [2] ff e1 [2] e3 e6 [2] ff c9 }

  condition:
    any of them
}