rule TTP_XOR_QUAD_CurrentVersionRun_56c1 {
  strings:
    $key_56c1 = { 05 ae [2] 21 a0 [2] 0a 8c [2] 24 ae [2] 30 b5 [2] 3f af [2] 21 b2 [2] 23 b3 [2] 38 b5 [2] 24 b2 [2] 38 9d }

  condition:
    any of them
}