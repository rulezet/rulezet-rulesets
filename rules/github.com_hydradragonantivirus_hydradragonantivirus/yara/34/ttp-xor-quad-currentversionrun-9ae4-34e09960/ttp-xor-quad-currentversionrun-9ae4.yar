rule TTP_XOR_QUAD_CurrentVersionRun_9ae4 {
  strings:
    $key_9ae4 = { c9 8b [2] ed 85 [2] c6 a9 [2] e8 8b [2] fc 90 [2] f3 8a [2] ed 97 [2] ef 96 [2] f4 90 [2] e8 97 [2] f4 b8 }

  condition:
    any of them
}