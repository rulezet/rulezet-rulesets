rule TTP_XOR_QUAD_CurrentVersionRun_49c0 {
  strings:
    $key_49c0 = { 1a af [2] 3e a1 [2] 15 8d [2] 3b af [2] 2f b4 [2] 20 ae [2] 3e b3 [2] 3c b2 [2] 27 b4 [2] 3b b3 [2] 27 9c }

  condition:
    any of them
}