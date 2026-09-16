rule TTP_XOR_QUAD_CurrentVersionRun_7ec0 {
  strings:
    $key_7ec0 = { 2d af [2] 09 a1 [2] 22 8d [2] 0c af [2] 18 b4 [2] 17 ae [2] 09 b3 [2] 0b b2 [2] 10 b4 [2] 0c b3 [2] 10 9c }

  condition:
    any of them
}