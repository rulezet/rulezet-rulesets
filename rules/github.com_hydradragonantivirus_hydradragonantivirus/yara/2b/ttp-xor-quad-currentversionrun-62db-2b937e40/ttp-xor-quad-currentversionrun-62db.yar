rule TTP_XOR_QUAD_CurrentVersionRun_62db {
  strings:
    $key_62db = { 31 b4 [2] 15 ba [2] 3e 96 [2] 10 b4 [2] 04 af [2] 0b b5 [2] 15 a8 [2] 17 a9 [2] 0c af [2] 10 a8 [2] 0c 87 }

  condition:
    any of them
}