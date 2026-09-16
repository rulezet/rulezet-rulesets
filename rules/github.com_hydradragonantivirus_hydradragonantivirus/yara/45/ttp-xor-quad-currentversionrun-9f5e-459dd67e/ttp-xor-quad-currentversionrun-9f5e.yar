rule TTP_XOR_QUAD_CurrentVersionRun_9f5e {
  strings:
    $key_9f5e = { cc 31 [2] e8 3f [2] c3 13 [2] ed 31 [2] f9 2a [2] f6 30 [2] e8 2d [2] ea 2c [2] f1 2a [2] ed 2d [2] f1 02 }

  condition:
    any of them
}