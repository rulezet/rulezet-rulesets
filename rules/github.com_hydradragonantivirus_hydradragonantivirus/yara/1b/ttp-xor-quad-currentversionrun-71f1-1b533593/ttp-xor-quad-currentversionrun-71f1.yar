rule TTP_XOR_QUAD_CurrentVersionRun_71f1 {
  strings:
    $key_71f1 = { 22 9e [2] 06 90 [2] 2d bc [2] 03 9e [2] 17 85 [2] 18 9f [2] 06 82 [2] 04 83 [2] 1f 85 [2] 03 82 [2] 1f ad }

  condition:
    any of them
}