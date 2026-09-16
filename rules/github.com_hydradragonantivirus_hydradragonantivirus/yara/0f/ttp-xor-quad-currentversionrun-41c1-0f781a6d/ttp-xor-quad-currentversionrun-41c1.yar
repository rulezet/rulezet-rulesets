rule TTP_XOR_QUAD_CurrentVersionRun_41c1 {
  strings:
    $key_41c1 = { 12 ae [2] 36 a0 [2] 1d 8c [2] 33 ae [2] 27 b5 [2] 28 af [2] 36 b2 [2] 34 b3 [2] 2f b5 [2] 33 b2 [2] 2f 9d }

  condition:
    any of them
}