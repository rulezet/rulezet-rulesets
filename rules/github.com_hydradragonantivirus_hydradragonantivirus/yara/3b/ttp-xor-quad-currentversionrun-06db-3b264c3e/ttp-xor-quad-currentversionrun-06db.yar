rule TTP_XOR_QUAD_CurrentVersionRun_06db {
  strings:
    $key_06db = { 55 b4 [2] 71 ba [2] 5a 96 [2] 74 b4 [2] 60 af [2] 6f b5 [2] 71 a8 [2] 73 a9 [2] 68 af [2] 74 a8 [2] 68 87 }

  condition:
    any of them
}