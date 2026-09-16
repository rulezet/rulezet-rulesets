rule TTP_XOR_QUAD_CurrentVersionRun_60db {
  strings:
    $key_60db = { 33 b4 [2] 17 ba [2] 3c 96 [2] 12 b4 [2] 06 af [2] 09 b5 [2] 17 a8 [2] 15 a9 [2] 0e af [2] 12 a8 [2] 0e 87 }

  condition:
    any of them
}