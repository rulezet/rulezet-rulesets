rule TTP_XOR_QUAD_CurrentVersionRun_83db {
  strings:
    $key_83db = { d0 b4 [2] f4 ba [2] df 96 [2] f1 b4 [2] e5 af [2] ea b5 [2] f4 a8 [2] f6 a9 [2] ed af [2] f1 a8 [2] ed 87 }

  condition:
    any of them
}