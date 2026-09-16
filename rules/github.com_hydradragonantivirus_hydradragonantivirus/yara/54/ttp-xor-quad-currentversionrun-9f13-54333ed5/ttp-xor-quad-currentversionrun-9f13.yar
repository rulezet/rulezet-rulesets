rule TTP_XOR_QUAD_CurrentVersionRun_9f13 {
  strings:
    $key_9f13 = { cc 7c [2] e8 72 [2] c3 5e [2] ed 7c [2] f9 67 [2] f6 7d [2] e8 60 [2] ea 61 [2] f1 67 [2] ed 60 [2] f1 4f }

  condition:
    any of them
}