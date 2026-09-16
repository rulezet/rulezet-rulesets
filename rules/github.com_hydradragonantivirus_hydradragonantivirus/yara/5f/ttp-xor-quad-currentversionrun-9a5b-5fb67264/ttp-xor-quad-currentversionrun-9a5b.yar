rule TTP_XOR_QUAD_CurrentVersionRun_9a5b {
  strings:
    $key_9a5b = { c9 34 [2] ed 3a [2] c6 16 [2] e8 34 [2] fc 2f [2] f3 35 [2] ed 28 [2] ef 29 [2] f4 2f [2] e8 28 [2] f4 07 }

  condition:
    any of them
}