rule TTP_XOR_QUAD_CurrentVersionRun_9294 {
  strings:
    $key_9294 = { c1 fb [2] e5 f5 [2] ce d9 [2] e0 fb [2] f4 e0 [2] fb fa [2] e5 e7 [2] e7 e6 [2] fc e0 [2] e0 e7 [2] fc c8 }

  condition:
    any of them
}