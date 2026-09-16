rule TTP_XOR_QUAD_CurrentVersionRun_34c0 {
  strings:
    $key_34c0 = { 67 af [2] 43 a1 [2] 68 8d [2] 46 af [2] 52 b4 [2] 5d ae [2] 43 b3 [2] 41 b2 [2] 5a b4 [2] 46 b3 [2] 5a 9c }

  condition:
    any of them
}