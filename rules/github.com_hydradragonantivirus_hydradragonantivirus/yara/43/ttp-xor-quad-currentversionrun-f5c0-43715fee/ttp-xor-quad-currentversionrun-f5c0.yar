rule TTP_XOR_QUAD_CurrentVersionRun_f5c0 {
  strings:
    $key_f5c0 = { a6 af [2] 82 a1 [2] a9 8d [2] 87 af [2] 93 b4 [2] 9c ae [2] 82 b3 [2] 80 b2 [2] 9b b4 [2] 87 b3 [2] 9b 9c }

  condition:
    any of them
}