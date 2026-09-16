rule TTP_XOR_QUAD_CurrentVersionRun_25db {
  strings:
    $key_25db = { 76 b4 [2] 52 ba [2] 79 96 [2] 57 b4 [2] 43 af [2] 4c b5 [2] 52 a8 [2] 50 a9 [2] 4b af [2] 57 a8 [2] 4b 87 }

  condition:
    any of them
}