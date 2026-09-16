rule TTP_XOR_QUAD_CurrentVersionRun_9a1b {
  strings:
    $key_9a1b = { c9 74 [2] ed 7a [2] c6 56 [2] e8 74 [2] fc 6f [2] f3 75 [2] ed 68 [2] ef 69 [2] f4 6f [2] e8 68 [2] f4 47 }

  condition:
    any of them
}