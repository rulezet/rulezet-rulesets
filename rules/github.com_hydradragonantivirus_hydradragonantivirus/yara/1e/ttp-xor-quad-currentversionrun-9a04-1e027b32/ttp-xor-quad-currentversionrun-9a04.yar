rule TTP_XOR_QUAD_CurrentVersionRun_9a04 {
  strings:
    $key_9a04 = { c9 6b [2] ed 65 [2] c6 49 [2] e8 6b [2] fc 70 [2] f3 6a [2] ed 77 [2] ef 76 [2] f4 70 [2] e8 77 [2] f4 58 }

  condition:
    any of them
}