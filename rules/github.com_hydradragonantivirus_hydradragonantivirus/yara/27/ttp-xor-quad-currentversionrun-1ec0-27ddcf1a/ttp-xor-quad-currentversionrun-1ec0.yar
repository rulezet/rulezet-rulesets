rule TTP_XOR_QUAD_CurrentVersionRun_1ec0 {
  strings:
    $key_1ec0 = { 4d af [2] 69 a1 [2] 42 8d [2] 6c af [2] 78 b4 [2] 77 ae [2] 69 b3 [2] 6b b2 [2] 70 b4 [2] 6c b3 [2] 70 9c }

  condition:
    any of them
}