rule TTP_XOR_QUAD_CurrentVersionRun_71f8 {
  strings:
    $key_71f8 = { 22 97 [2] 06 99 [2] 2d b5 [2] 03 97 [2] 17 8c [2] 18 96 [2] 06 8b [2] 04 8a [2] 1f 8c [2] 03 8b [2] 1f a4 }

  condition:
    any of them
}