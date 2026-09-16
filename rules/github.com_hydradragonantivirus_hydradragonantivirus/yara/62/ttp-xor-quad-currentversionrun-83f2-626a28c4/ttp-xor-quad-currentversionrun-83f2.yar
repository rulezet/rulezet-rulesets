rule TTP_XOR_QUAD_CurrentVersionRun_83f2 {
  strings:
    $key_83f2 = { d0 9d [2] f4 93 [2] df bf [2] f1 9d [2] e5 86 [2] ea 9c [2] f4 81 [2] f6 80 [2] ed 86 [2] f1 81 [2] ed ae }

  condition:
    any of them
}