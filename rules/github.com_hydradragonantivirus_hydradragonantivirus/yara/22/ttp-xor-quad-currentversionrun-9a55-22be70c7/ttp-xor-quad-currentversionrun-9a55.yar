rule TTP_XOR_QUAD_CurrentVersionRun_9a55 {
  strings:
    $key_9a55 = { c9 3a [2] ed 34 [2] c6 18 [2] e8 3a [2] fc 21 [2] f3 3b [2] ed 26 [2] ef 27 [2] f4 21 [2] e8 26 [2] f4 09 }

  condition:
    any of them
}