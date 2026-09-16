rule TTP_XOR_QUAD_CurrentVersionRun_9a06 {
  strings:
    $key_9a06 = { c9 69 [2] ed 67 [2] c6 4b [2] e8 69 [2] fc 72 [2] f3 68 [2] ed 75 [2] ef 74 [2] f4 72 [2] e8 75 [2] f4 5a }

  condition:
    any of them
}