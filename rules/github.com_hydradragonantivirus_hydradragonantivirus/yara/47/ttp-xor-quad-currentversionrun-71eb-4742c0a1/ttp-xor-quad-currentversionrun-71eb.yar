rule TTP_XOR_QUAD_CurrentVersionRun_71eb {
  strings:
    $key_71eb = { 22 84 [2] 06 8a [2] 2d a6 [2] 03 84 [2] 17 9f [2] 18 85 [2] 06 98 [2] 04 99 [2] 1f 9f [2] 03 98 [2] 1f b7 }

  condition:
    any of them
}