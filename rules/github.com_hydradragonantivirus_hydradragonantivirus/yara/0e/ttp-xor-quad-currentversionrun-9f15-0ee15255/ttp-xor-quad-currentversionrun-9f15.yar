rule TTP_XOR_QUAD_CurrentVersionRun_9f15 {
  strings:
    $key_9f15 = { cc 7a [2] e8 74 [2] c3 58 [2] ed 7a [2] f9 61 [2] f6 7b [2] e8 66 [2] ea 67 [2] f1 61 [2] ed 66 [2] f1 49 }

  condition:
    any of them
}