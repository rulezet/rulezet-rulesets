rule TTP_XOR_QUAD_CurrentVersionRun_76db {
  strings:
    $key_76db = { 25 b4 [2] 01 ba [2] 2a 96 [2] 04 b4 [2] 10 af [2] 1f b5 [2] 01 a8 [2] 03 a9 [2] 18 af [2] 04 a8 [2] 18 87 }

  condition:
    any of them
}