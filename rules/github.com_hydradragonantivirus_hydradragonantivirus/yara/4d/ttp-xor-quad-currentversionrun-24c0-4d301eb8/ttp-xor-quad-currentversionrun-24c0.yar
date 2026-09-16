rule TTP_XOR_QUAD_CurrentVersionRun_24c0 {
  strings:
    $key_24c0 = { 77 af [2] 53 a1 [2] 78 8d [2] 56 af [2] 42 b4 [2] 4d ae [2] 53 b3 [2] 51 b2 [2] 4a b4 [2] 56 b3 [2] 4a 9c }

  condition:
    any of them
}