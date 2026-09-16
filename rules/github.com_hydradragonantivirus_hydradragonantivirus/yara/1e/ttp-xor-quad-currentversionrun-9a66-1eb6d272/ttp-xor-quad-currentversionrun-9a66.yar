rule TTP_XOR_QUAD_CurrentVersionRun_9a66 {
  strings:
    $key_9a66 = { c9 09 [2] ed 07 [2] c6 2b [2] e8 09 [2] fc 12 [2] f3 08 [2] ed 15 [2] ef 14 [2] f4 12 [2] e8 15 [2] f4 3a }

  condition:
    any of them
}