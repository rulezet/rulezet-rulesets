rule TTP_XOR_QUAD_CurrentVersionRun_65db {
  strings:
    $key_65db = { 36 b4 [2] 12 ba [2] 39 96 [2] 17 b4 [2] 03 af [2] 0c b5 [2] 12 a8 [2] 10 a9 [2] 0b af [2] 17 a8 [2] 0b 87 }

  condition:
    any of them
}