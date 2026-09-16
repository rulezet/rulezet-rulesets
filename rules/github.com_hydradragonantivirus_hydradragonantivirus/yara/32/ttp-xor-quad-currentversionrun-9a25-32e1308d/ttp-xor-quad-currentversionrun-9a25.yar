rule TTP_XOR_QUAD_CurrentVersionRun_9a25 {
  strings:
    $key_9a25 = { c9 4a [2] ed 44 [2] c6 68 [2] e8 4a [2] fc 51 [2] f3 4b [2] ed 56 [2] ef 57 [2] f4 51 [2] e8 56 [2] f4 79 }

  condition:
    any of them
}