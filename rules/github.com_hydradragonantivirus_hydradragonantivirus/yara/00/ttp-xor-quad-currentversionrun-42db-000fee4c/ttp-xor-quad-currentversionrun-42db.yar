rule TTP_XOR_QUAD_CurrentVersionRun_42db {
  strings:
    $key_42db = { 11 b4 [2] 35 ba [2] 1e 96 [2] 30 b4 [2] 24 af [2] 2b b5 [2] 35 a8 [2] 37 a9 [2] 2c af [2] 30 a8 [2] 2c 87 }

  condition:
    any of them
}