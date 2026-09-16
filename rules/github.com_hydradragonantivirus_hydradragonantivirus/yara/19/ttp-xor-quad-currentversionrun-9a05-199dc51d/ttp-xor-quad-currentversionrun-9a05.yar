rule TTP_XOR_QUAD_CurrentVersionRun_9a05 {
  strings:
    $key_9a05 = { c9 6a [2] ed 64 [2] c6 48 [2] e8 6a [2] fc 71 [2] f3 6b [2] ed 76 [2] ef 77 [2] f4 71 [2] e8 76 [2] f4 59 }

  condition:
    any of them
}