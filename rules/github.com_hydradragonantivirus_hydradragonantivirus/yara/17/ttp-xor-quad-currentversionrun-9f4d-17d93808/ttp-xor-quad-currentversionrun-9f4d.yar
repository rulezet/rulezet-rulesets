rule TTP_XOR_QUAD_CurrentVersionRun_9f4d {
  strings:
    $key_9f4d = { cc 22 [2] e8 2c [2] c3 00 [2] ed 22 [2] f9 39 [2] f6 23 [2] e8 3e [2] ea 3f [2] f1 39 [2] ed 3e [2] f1 11 }

  condition:
    any of them
}