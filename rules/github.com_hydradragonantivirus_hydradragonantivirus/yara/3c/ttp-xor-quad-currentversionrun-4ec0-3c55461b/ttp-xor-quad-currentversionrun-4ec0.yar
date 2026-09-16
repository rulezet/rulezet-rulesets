rule TTP_XOR_QUAD_CurrentVersionRun_4ec0 {
  strings:
    $key_4ec0 = { 1d af [2] 39 a1 [2] 12 8d [2] 3c af [2] 28 b4 [2] 27 ae [2] 39 b3 [2] 3b b2 [2] 20 b4 [2] 3c b3 [2] 20 9c }

  condition:
    any of them
}