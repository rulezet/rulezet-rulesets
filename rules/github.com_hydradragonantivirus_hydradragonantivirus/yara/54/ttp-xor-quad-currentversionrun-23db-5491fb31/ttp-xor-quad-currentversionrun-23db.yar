rule TTP_XOR_QUAD_CurrentVersionRun_23db {
  strings:
    $key_23db = { 70 b4 [2] 54 ba [2] 7f 96 [2] 51 b4 [2] 45 af [2] 4a b5 [2] 54 a8 [2] 56 a9 [2] 4d af [2] 51 a8 [2] 4d 87 }

  condition:
    any of them
}