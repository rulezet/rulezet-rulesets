rule TTP_XOR_QUAD_CurrentVersionRun_4bdb {
  strings:
    $key_4bdb = { 18 b4 [2] 3c ba [2] 17 96 [2] 39 b4 [2] 2d af [2] 22 b5 [2] 3c a8 [2] 3e a9 [2] 25 af [2] 39 a8 [2] 25 87 }

  condition:
    any of them
}