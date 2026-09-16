rule TTP_XOR_QUAD_CurrentVersionRun_9a07 {
  strings:
    $key_9a07 = { c9 68 [2] ed 66 [2] c6 4a [2] e8 68 [2] fc 73 [2] f3 69 [2] ed 74 [2] ef 75 [2] f4 73 [2] e8 74 [2] f4 5b }

  condition:
    any of them
}