rule TTP_XOR_QUAD_CurrentVersionRun_9f33 {
  strings:
    $key_9f33 = { cc 5c [2] e8 52 [2] c3 7e [2] ed 5c [2] f9 47 [2] f6 5d [2] e8 40 [2] ea 41 [2] f1 47 [2] ed 40 [2] f1 6f }

  condition:
    any of them
}