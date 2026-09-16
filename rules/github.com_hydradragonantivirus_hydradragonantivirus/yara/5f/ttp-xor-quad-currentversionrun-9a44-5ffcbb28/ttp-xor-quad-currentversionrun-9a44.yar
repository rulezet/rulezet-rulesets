rule TTP_XOR_QUAD_CurrentVersionRun_9a44 {
  strings:
    $key_9a44 = { c9 2b [2] ed 25 [2] c6 09 [2] e8 2b [2] fc 30 [2] f3 2a [2] ed 37 [2] ef 36 [2] f4 30 [2] e8 37 [2] f4 18 }

  condition:
    any of them
}