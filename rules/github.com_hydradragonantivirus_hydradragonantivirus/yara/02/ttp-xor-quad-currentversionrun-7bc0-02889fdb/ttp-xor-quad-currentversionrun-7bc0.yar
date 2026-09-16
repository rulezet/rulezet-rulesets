rule TTP_XOR_QUAD_CurrentVersionRun_7bc0 {
  strings:
    $key_7bc0 = { 28 af [2] 0c a1 [2] 27 8d [2] 09 af [2] 1d b4 [2] 12 ae [2] 0c b3 [2] 0e b2 [2] 15 b4 [2] 09 b3 [2] 15 9c }

  condition:
    any of them
}