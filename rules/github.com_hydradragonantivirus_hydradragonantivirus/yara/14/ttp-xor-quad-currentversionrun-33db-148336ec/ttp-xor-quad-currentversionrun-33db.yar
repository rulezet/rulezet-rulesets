rule TTP_XOR_QUAD_CurrentVersionRun_33db {
  strings:
    $key_33db = { 60 b4 [2] 44 ba [2] 6f 96 [2] 41 b4 [2] 55 af [2] 5a b5 [2] 44 a8 [2] 46 a9 [2] 5d af [2] 41 a8 [2] 5d 87 }

  condition:
    any of them
}