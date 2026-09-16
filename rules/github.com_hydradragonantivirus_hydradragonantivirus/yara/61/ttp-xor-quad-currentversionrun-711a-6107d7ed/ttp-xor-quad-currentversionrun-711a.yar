rule TTP_XOR_QUAD_CurrentVersionRun_711a {
  strings:
    $key_711a = { 22 75 [2] 06 7b [2] 2d 57 [2] 03 75 [2] 17 6e [2] 18 74 [2] 06 69 [2] 04 68 [2] 1f 6e [2] 03 69 [2] 1f 46 }

  condition:
    any of them
}