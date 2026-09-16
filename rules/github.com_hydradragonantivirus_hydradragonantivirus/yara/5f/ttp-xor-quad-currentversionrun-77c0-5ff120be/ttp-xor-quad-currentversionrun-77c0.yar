rule TTP_XOR_QUAD_CurrentVersionRun_77c0 {
  strings:
    $key_77c0 = { 24 af [2] 00 a1 [2] 2b 8d [2] 05 af [2] 11 b4 [2] 1e ae [2] 00 b3 [2] 02 b2 [2] 19 b4 [2] 05 b3 [2] 19 9c }

  condition:
    any of them
}