rule TTP_XOR_QUAD_CurrentVersionRun_85db {
  strings:
    $key_85db = { d6 b4 [2] f2 ba [2] d9 96 [2] f7 b4 [2] e3 af [2] ec b5 [2] f2 a8 [2] f0 a9 [2] eb af [2] f7 a8 [2] eb 87 }

  condition:
    any of them
}