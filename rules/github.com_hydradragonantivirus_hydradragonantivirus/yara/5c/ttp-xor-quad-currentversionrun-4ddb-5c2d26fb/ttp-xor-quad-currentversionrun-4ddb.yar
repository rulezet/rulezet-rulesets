rule TTP_XOR_QUAD_CurrentVersionRun_4ddb {
  strings:
    $key_4ddb = { 1e b4 [2] 3a ba [2] 11 96 [2] 3f b4 [2] 2b af [2] 24 b5 [2] 3a a8 [2] 38 a9 [2] 23 af [2] 3f a8 [2] 23 87 }

  condition:
    any of them
}