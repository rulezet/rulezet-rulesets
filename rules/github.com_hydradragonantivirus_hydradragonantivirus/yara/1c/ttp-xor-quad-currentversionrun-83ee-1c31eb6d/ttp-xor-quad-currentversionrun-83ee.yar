rule TTP_XOR_QUAD_CurrentVersionRun_83ee {
  strings:
    $key_83ee = { d0 81 [2] f4 8f [2] df a3 [2] f1 81 [2] e5 9a [2] ea 80 [2] f4 9d [2] f6 9c [2] ed 9a [2] f1 9d [2] ed b2 }

  condition:
    any of them
}