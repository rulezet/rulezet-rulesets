rule TTP_XOR_QUAD_CurrentVersionRun_66c0 {
  strings:
    $key_66c0 = { 35 af [2] 11 a1 [2] 3a 8d [2] 14 af [2] 00 b4 [2] 0f ae [2] 11 b3 [2] 13 b2 [2] 08 b4 [2] 14 b3 [2] 08 9c }

  condition:
    any of them
}