rule TTP_XOR_QUAD_CurrentVersionRun_58dd {
  strings:
    $key_58dd = { 0b b2 [2] 2f bc [2] 04 90 [2] 2a b2 [2] 3e a9 [2] 31 b3 [2] 2f ae [2] 2d af [2] 36 a9 [2] 2a ae [2] 36 81 }

  condition:
    any of them
}