rule TTP_XOR_QUAD_CurrentVersionRun_7fdb {
  strings:
    $key_7fdb = { 2c b4 [2] 08 ba [2] 23 96 [2] 0d b4 [2] 19 af [2] 16 b5 [2] 08 a8 [2] 0a a9 [2] 11 af [2] 0d a8 [2] 11 87 }

  condition:
    any of them
}