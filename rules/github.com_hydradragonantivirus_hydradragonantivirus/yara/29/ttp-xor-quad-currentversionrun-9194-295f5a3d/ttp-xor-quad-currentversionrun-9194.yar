rule TTP_XOR_QUAD_CurrentVersionRun_9194 {
  strings:
    $key_9194 = { c2 fb [2] e6 f5 [2] cd d9 [2] e3 fb [2] f7 e0 [2] f8 fa [2] e6 e7 [2] e4 e6 [2] ff e0 [2] e3 e7 [2] ff c8 }

  condition:
    any of them
}