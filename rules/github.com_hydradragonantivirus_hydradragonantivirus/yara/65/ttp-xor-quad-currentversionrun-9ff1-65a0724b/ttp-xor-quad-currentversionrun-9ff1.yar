rule TTP_XOR_QUAD_CurrentVersionRun_9ff1 {
  strings:
    $key_9ff1 = { cc 9e [2] e8 90 [2] c3 bc [2] ed 9e [2] f9 85 [2] f6 9f [2] e8 82 [2] ea 83 [2] f1 85 [2] ed 82 [2] f1 ad }

  condition:
    any of them
}