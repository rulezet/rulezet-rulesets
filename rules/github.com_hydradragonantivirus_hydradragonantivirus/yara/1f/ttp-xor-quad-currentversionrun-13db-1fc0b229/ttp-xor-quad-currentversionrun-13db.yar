rule TTP_XOR_QUAD_CurrentVersionRun_13db {
  strings:
    $key_13db = { 40 b4 [2] 64 ba [2] 4f 96 [2] 61 b4 [2] 75 af [2] 7a b5 [2] 64 a8 [2] 66 a9 [2] 7d af [2] 61 a8 [2] 7d 87 }

  condition:
    any of them
}