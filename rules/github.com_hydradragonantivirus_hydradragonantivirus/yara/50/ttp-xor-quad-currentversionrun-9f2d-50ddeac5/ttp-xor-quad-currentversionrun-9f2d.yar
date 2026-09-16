rule TTP_XOR_QUAD_CurrentVersionRun_9f2d {
  strings:
    $key_9f2d = { cc 42 [2] e8 4c [2] c3 60 [2] ed 42 [2] f9 59 [2] f6 43 [2] e8 5e [2] ea 5f [2] f1 59 [2] ed 5e [2] f1 71 }

  condition:
    any of them
}