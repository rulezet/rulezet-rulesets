rule TTP_XOR_QUAD_CurrentVersionRun_f4db {
  strings:
    $key_f4db = { a7 b4 [2] 83 ba [2] a8 96 [2] 86 b4 [2] 92 af [2] 9d b5 [2] 83 a8 [2] 81 a9 [2] 9a af [2] 86 a8 [2] 9a 87 }

  condition:
    any of them
}