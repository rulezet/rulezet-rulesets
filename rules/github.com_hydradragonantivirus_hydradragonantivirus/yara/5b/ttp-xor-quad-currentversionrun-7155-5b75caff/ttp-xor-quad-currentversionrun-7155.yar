rule TTP_XOR_QUAD_CurrentVersionRun_7155 {
  strings:
    $key_7155 = { 22 3a [2] 06 34 [2] 2d 18 [2] 03 3a [2] 17 21 [2] 18 3b [2] 06 26 [2] 04 27 [2] 1f 21 [2] 03 26 [2] 1f 09 }

  condition:
    any of them
}