rule TTP_XOR_QUAD_CurrentVersionRun_9f02 {
  strings:
    $key_9f02 = { cc 6d [2] e8 63 [2] c3 4f [2] ed 6d [2] f9 76 [2] f6 6c [2] e8 71 [2] ea 70 [2] f1 76 [2] ed 71 [2] f1 5e }

  condition:
    any of them
}