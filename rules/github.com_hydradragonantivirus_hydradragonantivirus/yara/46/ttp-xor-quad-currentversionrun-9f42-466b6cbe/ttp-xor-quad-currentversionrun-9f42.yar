rule TTP_XOR_QUAD_CurrentVersionRun_9f42 {
  strings:
    $key_9f42 = { cc 2d [2] e8 23 [2] c3 0f [2] ed 2d [2] f9 36 [2] f6 2c [2] e8 31 [2] ea 30 [2] f1 36 [2] ed 31 [2] f1 1e }

  condition:
    any of them
}