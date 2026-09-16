rule TTP_XOR_QUAD_CurrentVersionRun_2ec0 {
  strings:
    $key_2ec0 = { 7d af [2] 59 a1 [2] 72 8d [2] 5c af [2] 48 b4 [2] 47 ae [2] 59 b3 [2] 5b b2 [2] 40 b4 [2] 5c b3 [2] 40 9c }

  condition:
    any of them
}