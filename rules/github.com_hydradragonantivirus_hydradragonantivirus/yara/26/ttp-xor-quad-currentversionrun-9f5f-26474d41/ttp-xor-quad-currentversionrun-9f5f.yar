rule TTP_XOR_QUAD_CurrentVersionRun_9f5f {
  strings:
    $key_9f5f = { cc 30 [2] e8 3e [2] c3 12 [2] ed 30 [2] f9 2b [2] f6 31 [2] e8 2c [2] ea 2d [2] f1 2b [2] ed 2c [2] f1 03 }

  condition:
    any of them
}