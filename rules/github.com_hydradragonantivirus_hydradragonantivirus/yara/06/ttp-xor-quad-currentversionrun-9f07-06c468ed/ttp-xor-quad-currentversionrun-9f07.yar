rule TTP_XOR_QUAD_CurrentVersionRun_9f07 {
  strings:
    $key_9f07 = { cc 68 [2] e8 66 [2] c3 4a [2] ed 68 [2] f9 73 [2] f6 69 [2] e8 74 [2] ea 75 [2] f1 73 [2] ed 74 [2] f1 5b }

  condition:
    any of them
}