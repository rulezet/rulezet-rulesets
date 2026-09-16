rule TTP_XOR_QUAD_CurrentVersionRun_4fdb {
  strings:
    $key_4fdb = { 1c b4 [2] 38 ba [2] 13 96 [2] 3d b4 [2] 29 af [2] 26 b5 [2] 38 a8 [2] 3a a9 [2] 21 af [2] 3d a8 [2] 21 87 }

  condition:
    any of them
}