rule TTP_XOR_QUAD_CurrentVersionRun_9ae5 {
  strings:
    $key_9ae5 = { c9 8a [2] ed 84 [2] c6 a8 [2] e8 8a [2] fc 91 [2] f3 8b [2] ed 96 [2] ef 97 [2] f4 91 [2] e8 96 [2] f4 b9 }

  condition:
    any of them
}