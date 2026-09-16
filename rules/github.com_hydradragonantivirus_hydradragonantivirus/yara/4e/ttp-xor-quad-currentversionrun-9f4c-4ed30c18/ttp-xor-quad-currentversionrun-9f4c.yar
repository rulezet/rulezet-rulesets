rule TTP_XOR_QUAD_CurrentVersionRun_9f4c {
  strings:
    $key_9f4c = { cc 23 [2] e8 2d [2] c3 01 [2] ed 23 [2] f9 38 [2] f6 22 [2] e8 3f [2] ea 3e [2] f1 38 [2] ed 3f [2] f1 10 }

  condition:
    any of them
}