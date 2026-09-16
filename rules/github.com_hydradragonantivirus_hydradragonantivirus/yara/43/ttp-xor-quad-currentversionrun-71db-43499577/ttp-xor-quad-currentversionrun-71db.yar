rule TTP_XOR_QUAD_CurrentVersionRun_71db {
  strings:
    $key_71db = { 22 b4 [2] 06 ba [2] 2d 96 [2] 03 b4 [2] 17 af [2] 18 b5 [2] 06 a8 [2] 04 a9 [2] 1f af [2] 03 a8 [2] 1f 87 }

  condition:
    any of them
}