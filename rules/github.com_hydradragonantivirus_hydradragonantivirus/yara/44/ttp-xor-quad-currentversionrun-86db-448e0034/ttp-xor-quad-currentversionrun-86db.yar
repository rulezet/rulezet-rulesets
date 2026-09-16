rule TTP_XOR_QUAD_CurrentVersionRun_86db {
  strings:
    $key_86db = { d5 b4 [2] f1 ba [2] da 96 [2] f4 b4 [2] e0 af [2] ef b5 [2] f1 a8 [2] f3 a9 [2] e8 af [2] f4 a8 [2] e8 87 }

  condition:
    any of them
}