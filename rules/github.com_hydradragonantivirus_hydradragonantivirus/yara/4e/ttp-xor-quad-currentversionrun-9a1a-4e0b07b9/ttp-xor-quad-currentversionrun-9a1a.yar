rule TTP_XOR_QUAD_CurrentVersionRun_9a1a {
  strings:
    $key_9a1a = { c9 75 [2] ed 7b [2] c6 57 [2] e8 75 [2] fc 6e [2] f3 74 [2] ed 69 [2] ef 68 [2] f4 6e [2] e8 69 [2] f4 46 }

  condition:
    any of them
}