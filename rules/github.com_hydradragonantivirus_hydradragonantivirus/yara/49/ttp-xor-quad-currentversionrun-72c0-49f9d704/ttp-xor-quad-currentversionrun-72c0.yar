rule TTP_XOR_QUAD_CurrentVersionRun_72c0 {
  strings:
    $key_72c0 = { 21 af [2] 05 a1 [2] 2e 8d [2] 00 af [2] 14 b4 [2] 1b ae [2] 05 b3 [2] 07 b2 [2] 1c b4 [2] 00 b3 [2] 1c 9c }

  condition:
    any of them
}