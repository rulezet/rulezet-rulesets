rule TTP_XOR_QUAD_CurrentVersionRun_9f47 {
  strings:
    $key_9f47 = { cc 28 [2] e8 26 [2] c3 0a [2] ed 28 [2] f9 33 [2] f6 29 [2] e8 34 [2] ea 35 [2] f1 33 [2] ed 34 [2] f1 1b }

  condition:
    any of them
}