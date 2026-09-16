rule TTP_XOR_QUAD_CurrentVersionRun_9f27 {
  strings:
    $key_9f27 = { cc 48 [2] e8 46 [2] c3 6a [2] ed 48 [2] f9 53 [2] f6 49 [2] e8 54 [2] ea 55 [2] f1 53 [2] ed 54 [2] f1 7b }

  condition:
    any of them
}