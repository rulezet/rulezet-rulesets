rule TTP_XOR_QUAD_CurrentVersionRun_12db {
  strings:
    $key_12db = { 41 b4 [2] 65 ba [2] 4e 96 [2] 60 b4 [2] 74 af [2] 7b b5 [2] 65 a8 [2] 67 a9 [2] 7c af [2] 60 a8 [2] 7c 87 }

  condition:
    any of them
}