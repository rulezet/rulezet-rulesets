rule TTP_XOR_QUAD_CurrentVersionRun_9a23 {
  strings:
    $key_9a23 = { c9 4c [2] ed 42 [2] c6 6e [2] e8 4c [2] fc 57 [2] f3 4d [2] ed 50 [2] ef 51 [2] f4 57 [2] e8 50 [2] f4 7f }

  condition:
    any of them
}