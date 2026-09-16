rule TTP_XOR_QUAD_CurrentVersionRun_47c0 {
  strings:
    $key_47c0 = { 14 af [2] 30 a1 [2] 1b 8d [2] 35 af [2] 21 b4 [2] 2e ae [2] 30 b3 [2] 32 b2 [2] 29 b4 [2] 35 b3 [2] 29 9c }

  condition:
    any of them
}