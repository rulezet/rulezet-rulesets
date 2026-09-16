rule TTP_XOR_QUAD_CurrentVersionRun_07db {
  strings:
    $key_07db = { 54 b4 [2] 70 ba [2] 5b 96 [2] 75 b4 [2] 61 af [2] 6e b5 [2] 70 a8 [2] 72 a9 [2] 69 af [2] 75 a8 [2] 69 87 }

  condition:
    any of them
}