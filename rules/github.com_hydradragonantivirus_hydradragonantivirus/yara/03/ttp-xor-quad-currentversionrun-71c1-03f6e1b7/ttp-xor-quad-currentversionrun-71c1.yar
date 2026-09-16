rule TTP_XOR_QUAD_CurrentVersionRun_71c1 {
  strings:
    $key_71c1 = { 22 ae [2] 06 a0 [2] 2d 8c [2] 03 ae [2] 17 b5 [2] 18 af [2] 06 b2 [2] 04 b3 [2] 1f b5 [2] 03 b2 [2] 1f 9d }

  condition:
    any of them
}