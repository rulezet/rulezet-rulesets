rule TTP_XOR_QUAD_CurrentVersionRun_54c1 {
  strings:
    $key_54c1 = { 07 ae [2] 23 a0 [2] 08 8c [2] 26 ae [2] 32 b5 [2] 3d af [2] 23 b2 [2] 21 b3 [2] 3a b5 [2] 26 b2 [2] 3a 9d }

  condition:
    any of them
}