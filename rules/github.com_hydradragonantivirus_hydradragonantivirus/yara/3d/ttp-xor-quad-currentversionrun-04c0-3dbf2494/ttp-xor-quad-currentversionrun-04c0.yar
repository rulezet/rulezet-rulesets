rule TTP_XOR_QUAD_CurrentVersionRun_04c0 {
  strings:
    $key_04c0 = { 57 af [2] 73 a1 [2] 58 8d [2] 76 af [2] 62 b4 [2] 6d ae [2] 73 b3 [2] 71 b2 [2] 6a b4 [2] 76 b3 [2] 6a 9c }

  condition:
    any of them
}