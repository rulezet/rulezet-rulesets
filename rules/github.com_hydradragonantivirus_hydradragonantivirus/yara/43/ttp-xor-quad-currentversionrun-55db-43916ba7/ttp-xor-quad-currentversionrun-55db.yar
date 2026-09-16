rule TTP_XOR_QUAD_CurrentVersionRun_55db {
  strings:
    $key_55db = { 06 b4 [2] 22 ba [2] 09 96 [2] 27 b4 [2] 33 af [2] 3c b5 [2] 22 a8 [2] 20 a9 [2] 3b af [2] 27 a8 [2] 3b 87 }

  condition:
    any of them
}