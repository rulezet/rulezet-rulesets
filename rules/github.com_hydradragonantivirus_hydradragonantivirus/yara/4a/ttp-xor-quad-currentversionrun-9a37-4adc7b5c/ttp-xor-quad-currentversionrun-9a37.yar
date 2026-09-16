rule TTP_XOR_QUAD_CurrentVersionRun_9a37 {
  strings:
    $key_9a37 = { c9 58 [2] ed 56 [2] c6 7a [2] e8 58 [2] fc 43 [2] f3 59 [2] ed 44 [2] ef 45 [2] f4 43 [2] e8 44 [2] f4 6b }

  condition:
    any of them
}