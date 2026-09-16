rule TTP_XOR_QUAD_CurrentVersionRun_9f7b {
  strings:
    $key_9f7b = { cc 14 [2] e8 1a [2] c3 36 [2] ed 14 [2] f9 0f [2] f6 15 [2] e8 08 [2] ea 09 [2] f1 0f [2] ed 08 [2] f1 27 }

  condition:
    any of them
}