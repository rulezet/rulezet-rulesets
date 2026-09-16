rule TTP_XOR_QUAD_CurrentVersionRun_83f3 {
  strings:
    $key_83f3 = { d0 9c [2] f4 92 [2] df be [2] f1 9c [2] e5 87 [2] ea 9d [2] f4 80 [2] f6 81 [2] ed 87 [2] f1 80 [2] ed af }

  condition:
    any of them
}