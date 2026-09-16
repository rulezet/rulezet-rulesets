rule TTP_XOR_QUAD_CurrentVersionRun_714a {
  strings:
    $key_714a = { 22 25 [2] 06 2b [2] 2d 07 [2] 03 25 [2] 17 3e [2] 18 24 [2] 06 39 [2] 04 38 [2] 1f 3e [2] 03 39 [2] 1f 16 }

  condition:
    any of them
}