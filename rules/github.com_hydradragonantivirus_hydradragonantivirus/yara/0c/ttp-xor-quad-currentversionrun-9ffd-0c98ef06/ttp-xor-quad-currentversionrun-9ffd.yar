rule TTP_XOR_QUAD_CurrentVersionRun_9ffd {
  strings:
    $key_9ffd = { cc 92 [2] e8 9c [2] c3 b0 [2] ed 92 [2] f9 89 [2] f6 93 [2] e8 8e [2] ea 8f [2] f1 89 [2] ed 8e [2] f1 a1 }

  condition:
    any of them
}