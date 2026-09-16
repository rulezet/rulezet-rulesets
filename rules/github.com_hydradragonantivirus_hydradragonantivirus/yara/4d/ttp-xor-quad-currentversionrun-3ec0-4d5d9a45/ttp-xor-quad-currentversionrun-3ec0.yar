rule TTP_XOR_QUAD_CurrentVersionRun_3ec0 {
  strings:
    $key_3ec0 = { 6d af [2] 49 a1 [2] 62 8d [2] 4c af [2] 58 b4 [2] 57 ae [2] 49 b3 [2] 4b b2 [2] 50 b4 [2] 4c b3 [2] 50 9c }

  condition:
    any of them
}