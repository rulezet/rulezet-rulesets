rule TTP_XOR_QUAD_CurrentVersionRun_9f22 {
  strings:
    $key_9f22 = { cc 4d [2] e8 43 [2] c3 6f [2] ed 4d [2] f9 56 [2] f6 4c [2] e8 51 [2] ea 50 [2] f1 56 [2] ed 51 [2] f1 7e }

  condition:
    any of them
}