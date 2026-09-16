rule TTP_XOR_QUAD_CurrentVersionRun_35c0 {
  strings:
    $key_35c0 = { 66 af [2] 42 a1 [2] 69 8d [2] 47 af [2] 53 b4 [2] 5c ae [2] 42 b3 [2] 40 b2 [2] 5b b4 [2] 47 b3 [2] 5b 9c }

  condition:
    any of them
}