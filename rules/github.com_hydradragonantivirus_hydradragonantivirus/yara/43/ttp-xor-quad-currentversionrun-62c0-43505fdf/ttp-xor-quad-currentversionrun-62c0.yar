rule TTP_XOR_QUAD_CurrentVersionRun_62c0 {
  strings:
    $key_62c0 = { 31 af [2] 15 a1 [2] 3e 8d [2] 10 af [2] 04 b4 [2] 0b ae [2] 15 b3 [2] 17 b2 [2] 0c b4 [2] 10 b3 [2] 0c 9c }

  condition:
    any of them
}