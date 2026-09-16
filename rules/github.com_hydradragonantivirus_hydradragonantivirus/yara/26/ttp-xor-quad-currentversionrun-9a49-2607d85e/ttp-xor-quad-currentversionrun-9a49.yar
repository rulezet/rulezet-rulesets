rule TTP_XOR_QUAD_CurrentVersionRun_9a49 {
  strings:
    $key_9a49 = { c9 26 [2] ed 28 [2] c6 04 [2] e8 26 [2] fc 3d [2] f3 27 [2] ed 3a [2] ef 3b [2] f4 3d [2] e8 3a [2] f4 15 }

  condition:
    any of them
}