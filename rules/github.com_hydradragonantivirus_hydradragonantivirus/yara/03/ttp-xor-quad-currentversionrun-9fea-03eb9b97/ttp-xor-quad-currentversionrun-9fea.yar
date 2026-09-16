rule TTP_XOR_QUAD_CurrentVersionRun_9fea {
  strings:
    $key_9fea = { cc 85 [2] e8 8b [2] c3 a7 [2] ed 85 [2] f9 9e [2] f6 84 [2] e8 99 [2] ea 98 [2] f1 9e [2] ed 99 [2] f1 b6 }

  condition:
    any of them
}