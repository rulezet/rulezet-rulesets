rule TTP_XOR_QUAD_CurrentVersionRun_82db {
  strings:
    $key_82db = { d1 b4 [2] f5 ba [2] de 96 [2] f0 b4 [2] e4 af [2] eb b5 [2] f5 a8 [2] f7 a9 [2] ec af [2] f0 a8 [2] ec 87 }

  condition:
    any of them
}