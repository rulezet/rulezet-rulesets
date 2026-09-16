rule TTP_XOR_QUAD_CurrentVersionRun_56c0 {
  strings:
    $key_56c0 = { 05 af [2] 21 a1 [2] 0a 8d [2] 24 af [2] 30 b4 [2] 3f ae [2] 21 b3 [2] 23 b2 [2] 38 b4 [2] 24 b3 [2] 38 9c }

  condition:
    any of them
}