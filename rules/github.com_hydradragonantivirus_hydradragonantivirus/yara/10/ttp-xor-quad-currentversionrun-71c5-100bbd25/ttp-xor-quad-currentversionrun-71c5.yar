rule TTP_XOR_QUAD_CurrentVersionRun_71c5 {
  strings:
    $key_71c5 = { 22 aa [2] 06 a4 [2] 2d 88 [2] 03 aa [2] 17 b1 [2] 18 ab [2] 06 b6 [2] 04 b7 [2] 1f b1 [2] 03 b6 [2] 1f 99 }

  condition:
    any of them
}