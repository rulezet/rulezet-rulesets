rule TTP_XOR_QUAD_CurrentVersionRun_54c0 {
  strings:
    $key_54c0 = { 07 af [2] 23 a1 [2] 08 8d [2] 26 af [2] 32 b4 [2] 3d ae [2] 23 b3 [2] 21 b2 [2] 3a b4 [2] 26 b3 [2] 3a 9c }

  condition:
    any of them
}