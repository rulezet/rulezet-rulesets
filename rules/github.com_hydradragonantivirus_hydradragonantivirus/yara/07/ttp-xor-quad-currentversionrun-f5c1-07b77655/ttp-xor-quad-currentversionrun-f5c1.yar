rule TTP_XOR_QUAD_CurrentVersionRun_f5c1 {
  strings:
    $key_f5c1 = { a6 ae [2] 82 a0 [2] a9 8c [2] 87 ae [2] 93 b5 [2] 9c af [2] 82 b2 [2] 80 b3 [2] 9b b5 [2] 87 b2 [2] 9b 9d }

  condition:
    any of them
}