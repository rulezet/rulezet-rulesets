rule TTP_XOR_QUAD_CurrentVersionRun_04c1 {
  strings:
    $key_04c1 = { 57 ae [2] 73 a0 [2] 58 8c [2] 76 ae [2] 62 b5 [2] 6d af [2] 73 b2 [2] 71 b3 [2] 6a b5 [2] 76 b2 [2] 6a 9d }

  condition:
    any of them
}