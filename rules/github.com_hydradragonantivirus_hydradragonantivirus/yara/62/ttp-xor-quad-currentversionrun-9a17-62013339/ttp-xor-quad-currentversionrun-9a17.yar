rule TTP_XOR_QUAD_CurrentVersionRun_9a17 {
  strings:
    $key_9a17 = { c9 78 [2] ed 76 [2] c6 5a [2] e8 78 [2] fc 63 [2] f3 79 [2] ed 64 [2] ef 65 [2] f4 63 [2] e8 64 [2] f4 4b }

  condition:
    any of them
}