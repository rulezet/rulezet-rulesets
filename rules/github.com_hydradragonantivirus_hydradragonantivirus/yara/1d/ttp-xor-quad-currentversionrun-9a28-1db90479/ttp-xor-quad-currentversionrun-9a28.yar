rule TTP_XOR_QUAD_CurrentVersionRun_9a28 {
  strings:
    $key_9a28 = { c9 47 [2] ed 49 [2] c6 65 [2] e8 47 [2] fc 5c [2] f3 46 [2] ed 5b [2] ef 5a [2] f4 5c [2] e8 5b [2] f4 74 }

  condition:
    any of them
}