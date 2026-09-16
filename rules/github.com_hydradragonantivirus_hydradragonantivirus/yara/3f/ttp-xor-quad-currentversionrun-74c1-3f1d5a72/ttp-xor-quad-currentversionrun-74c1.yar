rule TTP_XOR_QUAD_CurrentVersionRun_74c1 {
  strings:
    $key_74c1 = { 27 ae [2] 03 a0 [2] 28 8c [2] 06 ae [2] 12 b5 [2] 1d af [2] 03 b2 [2] 01 b3 [2] 1a b5 [2] 06 b2 [2] 1a 9d }

  condition:
    any of them
}