rule TTP_XOR_QUAD_CurrentVersionRun_74c0 {
  strings:
    $key_74c0 = { 27 af [2] 03 a1 [2] 28 8d [2] 06 af [2] 12 b4 [2] 1d ae [2] 03 b3 [2] 01 b2 [2] 1a b4 [2] 06 b3 [2] 1a 9c }

  condition:
    any of them
}