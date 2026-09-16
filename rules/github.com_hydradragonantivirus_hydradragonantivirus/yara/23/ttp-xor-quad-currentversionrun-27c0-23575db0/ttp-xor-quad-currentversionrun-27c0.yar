rule TTP_XOR_QUAD_CurrentVersionRun_27c0 {
  strings:
    $key_27c0 = { 74 af [2] 50 a1 [2] 7b 8d [2] 55 af [2] 41 b4 [2] 4e ae [2] 50 b3 [2] 52 b2 [2] 49 b4 [2] 55 b3 [2] 49 9c }

  condition:
    any of them
}