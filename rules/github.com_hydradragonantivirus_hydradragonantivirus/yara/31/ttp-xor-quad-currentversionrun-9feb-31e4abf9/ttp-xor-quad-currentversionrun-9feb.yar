rule TTP_XOR_QUAD_CurrentVersionRun_9feb {
  strings:
    $key_9feb = { cc 84 [2] e8 8a [2] c3 a6 [2] ed 84 [2] f9 9f [2] f6 85 [2] e8 98 [2] ea 99 [2] f1 9f [2] ed 98 [2] f1 b7 }

  condition:
    any of them
}