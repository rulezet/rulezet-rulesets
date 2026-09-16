rule TTP_XOR_QUAD_CurrentVersionRun_4bc0 {
  strings:
    $key_4bc0 = { 18 af [2] 3c a1 [2] 17 8d [2] 39 af [2] 2d b4 [2] 22 ae [2] 3c b3 [2] 3e b2 [2] 25 b4 [2] 39 b3 [2] 25 9c }

  condition:
    any of them
}