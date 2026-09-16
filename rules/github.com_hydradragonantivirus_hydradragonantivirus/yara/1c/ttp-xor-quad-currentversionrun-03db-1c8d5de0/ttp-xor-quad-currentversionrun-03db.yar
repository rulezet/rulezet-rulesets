rule TTP_XOR_QUAD_CurrentVersionRun_03db {
  strings:
    $key_03db = { 50 b4 [2] 74 ba [2] 5f 96 [2] 71 b4 [2] 65 af [2] 6a b5 [2] 74 a8 [2] 76 a9 [2] 6d af [2] 71 a8 [2] 6d 87 }

  condition:
    any of them
}