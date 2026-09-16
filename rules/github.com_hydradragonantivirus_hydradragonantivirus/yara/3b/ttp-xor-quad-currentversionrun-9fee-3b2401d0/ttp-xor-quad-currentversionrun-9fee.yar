rule TTP_XOR_QUAD_CurrentVersionRun_9fee {
  strings:
    $key_9fee = { cc 81 [2] e8 8f [2] c3 a3 [2] ed 81 [2] f9 9a [2] f6 80 [2] e8 9d [2] ea 9c [2] f1 9a [2] ed 9d [2] f1 b2 }

  condition:
    any of them
}