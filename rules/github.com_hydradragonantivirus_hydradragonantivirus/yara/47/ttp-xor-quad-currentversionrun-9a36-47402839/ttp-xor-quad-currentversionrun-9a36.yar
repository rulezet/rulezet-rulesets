rule TTP_XOR_QUAD_CurrentVersionRun_9a36 {
  strings:
    $key_9a36 = { c9 59 [2] ed 57 [2] c6 7b [2] e8 59 [2] fc 42 [2] f3 58 [2] ed 45 [2] ef 44 [2] f4 42 [2] e8 45 [2] f4 6a }

  condition:
    any of them
}