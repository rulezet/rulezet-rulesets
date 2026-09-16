rule TTP_XOR_QUAD_CurrentVersionRun_44db {
  strings:
    $key_44db = { 17 b4 [2] 33 ba [2] 18 96 [2] 36 b4 [2] 22 af [2] 2d b5 [2] 33 a8 [2] 31 a9 [2] 2a af [2] 36 a8 [2] 2a 87 }

  condition:
    any of them
}