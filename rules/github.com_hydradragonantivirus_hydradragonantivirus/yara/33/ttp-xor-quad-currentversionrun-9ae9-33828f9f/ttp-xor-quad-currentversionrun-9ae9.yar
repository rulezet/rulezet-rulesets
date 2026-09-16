rule TTP_XOR_QUAD_CurrentVersionRun_9ae9 {
  strings:
    $key_9ae9 = { c9 86 [2] ed 88 [2] c6 a4 [2] e8 86 [2] fc 9d [2] f3 87 [2] ed 9a [2] ef 9b [2] f4 9d [2] e8 9a [2] f4 b5 }

  condition:
    any of them
}