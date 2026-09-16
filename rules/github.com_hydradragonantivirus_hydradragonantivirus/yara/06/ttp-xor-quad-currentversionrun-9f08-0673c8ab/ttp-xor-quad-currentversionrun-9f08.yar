rule TTP_XOR_QUAD_CurrentVersionRun_9f08 {
  strings:
    $key_9f08 = { cc 67 [2] e8 69 [2] c3 45 [2] ed 67 [2] f9 7c [2] f6 66 [2] e8 7b [2] ea 7a [2] f1 7c [2] ed 7b [2] f1 54 }

  condition:
    any of them
}