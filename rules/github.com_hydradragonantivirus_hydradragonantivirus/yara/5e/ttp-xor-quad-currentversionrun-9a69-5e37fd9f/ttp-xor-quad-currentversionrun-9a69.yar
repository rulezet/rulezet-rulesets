rule TTP_XOR_QUAD_CurrentVersionRun_9a69 {
  strings:
    $key_9a69 = { c9 06 [2] ed 08 [2] c6 24 [2] e8 06 [2] fc 1d [2] f3 07 [2] ed 1a [2] ef 1b [2] f4 1d [2] e8 1a [2] f4 35 }

  condition:
    any of them
}