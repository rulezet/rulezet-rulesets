rule TTP_XOR_QUAD_CurrentVersionRun_92db {
  strings:
    $key_92db = { c1 b4 [2] e5 ba [2] ce 96 [2] e0 b4 [2] f4 af [2] fb b5 [2] e5 a8 [2] e7 a9 [2] fc af [2] e0 a8 [2] fc 87 }

  condition:
    any of them
}