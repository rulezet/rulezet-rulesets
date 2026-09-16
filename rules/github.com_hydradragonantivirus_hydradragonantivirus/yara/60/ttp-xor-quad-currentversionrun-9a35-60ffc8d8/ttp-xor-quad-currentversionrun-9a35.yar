rule TTP_XOR_QUAD_CurrentVersionRun_9a35 {
  strings:
    $key_9a35 = { c9 5a [2] ed 54 [2] c6 78 [2] e8 5a [2] fc 41 [2] f3 5b [2] ed 46 [2] ef 47 [2] f4 41 [2] e8 46 [2] f4 69 }

  condition:
    any of them
}