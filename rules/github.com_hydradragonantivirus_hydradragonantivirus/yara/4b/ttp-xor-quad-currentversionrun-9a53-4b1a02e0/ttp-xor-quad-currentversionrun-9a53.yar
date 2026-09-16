rule TTP_XOR_QUAD_CurrentVersionRun_9a53 {
  strings:
    $key_9a53 = { c9 3c [2] ed 32 [2] c6 1e [2] e8 3c [2] fc 27 [2] f3 3d [2] ed 20 [2] ef 21 [2] f4 27 [2] e8 20 [2] f4 0f }

  condition:
    any of them
}