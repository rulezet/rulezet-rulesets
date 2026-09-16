rule TTP_XOR_QUAD_CurrentVersionRun_07c0 {
  strings:
    $key_07c0 = { 54 af [2] 70 a1 [2] 5b 8d [2] 75 af [2] 61 b4 [2] 6e ae [2] 70 b3 [2] 72 b2 [2] 69 b4 [2] 75 b3 [2] 69 9c }

  condition:
    any of them
}