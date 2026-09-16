rule TTP_XOR_QUAD_CurrentVersionRun_55c1 {
  strings:
    $key_55c1 = { 06 ae [2] 22 a0 [2] 09 8c [2] 27 ae [2] 33 b5 [2] 3c af [2] 22 b2 [2] 20 b3 [2] 3b b5 [2] 27 b2 [2] 3b 9d }

  condition:
    any of them
}