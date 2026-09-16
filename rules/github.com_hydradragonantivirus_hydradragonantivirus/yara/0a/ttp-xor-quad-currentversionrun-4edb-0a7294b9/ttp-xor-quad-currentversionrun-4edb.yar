rule TTP_XOR_QUAD_CurrentVersionRun_4edb {
  strings:
    $key_4edb = { 1d b4 [2] 39 ba [2] 12 96 [2] 3c b4 [2] 28 af [2] 27 b5 [2] 39 a8 [2] 3b a9 [2] 20 af [2] 3c a8 [2] 20 87 }

  condition:
    any of them
}