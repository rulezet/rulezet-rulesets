rule TTP_XOR_QUAD_CurrentVersionRun_32c0 {
  strings:
    $key_32c0 = { 61 af [2] 45 a1 [2] 6e 8d [2] 40 af [2] 54 b4 [2] 5b ae [2] 45 b3 [2] 47 b2 [2] 5c b4 [2] 40 b3 [2] 5c 9c }

  condition:
    any of them
}