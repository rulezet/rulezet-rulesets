rule TTP_XOR_QUAD_CurrentVersionRun_7134 {
  strings:
    $key_7134 = { 22 5b [2] 06 55 [2] 2d 79 [2] 03 5b [2] 17 40 [2] 18 5a [2] 06 47 [2] 04 46 [2] 1f 40 [2] 03 47 [2] 1f 68 }

  condition:
    any of them
}