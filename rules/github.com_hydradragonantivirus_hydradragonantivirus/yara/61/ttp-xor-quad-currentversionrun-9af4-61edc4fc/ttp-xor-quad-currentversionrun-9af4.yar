rule TTP_XOR_QUAD_CurrentVersionRun_9af4 {
  strings:
    $key_9af4 = { c9 9b [2] ed 95 [2] c6 b9 [2] e8 9b [2] fc 80 [2] f3 9a [2] ed 87 [2] ef 86 [2] f4 80 [2] e8 87 [2] f4 a8 }

  condition:
    any of them
}