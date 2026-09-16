rule TTP_XOR_QUAD_CurrentVersionRun_74db {
  strings:
    $key_74db = { 27 b4 [2] 03 ba [2] 28 96 [2] 06 b4 [2] 12 af [2] 1d b5 [2] 03 a8 [2] 01 a9 [2] 1a af [2] 06 a8 [2] 1a 87 }

  condition:
    any of them
}