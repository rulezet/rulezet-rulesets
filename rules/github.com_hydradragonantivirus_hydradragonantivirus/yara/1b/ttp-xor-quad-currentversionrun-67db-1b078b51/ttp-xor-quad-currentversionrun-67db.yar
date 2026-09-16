rule TTP_XOR_QUAD_CurrentVersionRun_67db {
  strings:
    $key_67db = { 34 b4 [2] 10 ba [2] 3b 96 [2] 15 b4 [2] 01 af [2] 0e b5 [2] 10 a8 [2] 12 a9 [2] 09 af [2] 15 a8 [2] 09 87 }

  condition:
    any of them
}