rule TTP_XOR_QUAD_CurrentVersionRun_71c0 {
  strings:
    $key_71c0 = { 22 af [2] 06 a1 [2] 2d 8d [2] 03 af [2] 17 b4 [2] 18 ae [2] 06 b3 [2] 04 b2 [2] 1f b4 [2] 03 b3 [2] 1f 9c }

  condition:
    any of them
}