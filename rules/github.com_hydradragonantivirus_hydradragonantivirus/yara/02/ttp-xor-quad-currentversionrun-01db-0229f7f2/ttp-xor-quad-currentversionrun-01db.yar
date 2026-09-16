rule TTP_XOR_QUAD_CurrentVersionRun_01db {
  strings:
    $key_01db = { 52 b4 [2] 76 ba [2] 5d 96 [2] 73 b4 [2] 67 af [2] 68 b5 [2] 76 a8 [2] 74 a9 [2] 6f af [2] 73 a8 [2] 6f 87 }

  condition:
    any of them
}