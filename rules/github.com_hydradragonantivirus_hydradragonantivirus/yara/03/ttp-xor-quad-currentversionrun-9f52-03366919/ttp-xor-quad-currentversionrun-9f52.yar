rule TTP_XOR_QUAD_CurrentVersionRun_9f52 {
  strings:
    $key_9f52 = { cc 3d [2] e8 33 [2] c3 1f [2] ed 3d [2] f9 26 [2] f6 3c [2] e8 21 [2] ea 20 [2] f1 26 [2] ed 21 [2] f1 0e }

  condition:
    any of them
}