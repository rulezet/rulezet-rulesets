rule TTP_XOR_QUAD_CurrentVersionRun_61db {
  strings:
    $key_61db = { 32 b4 [2] 16 ba [2] 3d 96 [2] 13 b4 [2] 07 af [2] 08 b5 [2] 16 a8 [2] 14 a9 [2] 0f af [2] 13 a8 [2] 0f 87 }

  condition:
    any of them
}