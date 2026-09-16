rule TTP_XOR_QUAD_CurrentVersionRun_54db {
  strings:
    $key_54db = { 07 b4 [2] 23 ba [2] 08 96 [2] 26 b4 [2] 32 af [2] 3d b5 [2] 23 a8 [2] 21 a9 [2] 3a af [2] 26 a8 [2] 3a 87 }

  condition:
    any of them
}