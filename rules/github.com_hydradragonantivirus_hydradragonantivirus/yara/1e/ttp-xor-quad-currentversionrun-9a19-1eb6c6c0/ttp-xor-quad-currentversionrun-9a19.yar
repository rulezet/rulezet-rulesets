rule TTP_XOR_QUAD_CurrentVersionRun_9a19 {
  strings:
    $key_9a19 = { c9 76 [2] ed 78 [2] c6 54 [2] e8 76 [2] fc 6d [2] f3 77 [2] ed 6a [2] ef 6b [2] f4 6d [2] e8 6a [2] f4 45 }

  condition:
    any of them
}