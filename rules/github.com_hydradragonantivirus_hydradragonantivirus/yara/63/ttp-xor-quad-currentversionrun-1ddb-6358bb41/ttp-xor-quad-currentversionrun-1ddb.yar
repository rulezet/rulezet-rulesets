rule TTP_XOR_QUAD_CurrentVersionRun_1ddb {
  strings:
    $key_1ddb = { 4e b4 [2] 6a ba [2] 41 96 [2] 6f b4 [2] 7b af [2] 74 b5 [2] 6a a8 [2] 68 a9 [2] 73 af [2] 6f a8 [2] 73 87 }

  condition:
    any of them
}