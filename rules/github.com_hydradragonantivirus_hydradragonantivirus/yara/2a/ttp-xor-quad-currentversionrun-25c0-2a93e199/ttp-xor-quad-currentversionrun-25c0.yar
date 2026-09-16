rule TTP_XOR_QUAD_CurrentVersionRun_25c0 {
  strings:
    $key_25c0 = { 76 af [2] 52 a1 [2] 79 8d [2] 57 af [2] 43 b4 [2] 4c ae [2] 52 b3 [2] 50 b2 [2] 4b b4 [2] 57 b3 [2] 4b 9c }

  condition:
    any of them
}