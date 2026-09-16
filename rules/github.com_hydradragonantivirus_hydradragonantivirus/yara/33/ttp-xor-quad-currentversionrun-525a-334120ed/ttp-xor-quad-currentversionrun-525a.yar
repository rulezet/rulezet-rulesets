rule TTP_XOR_QUAD_CurrentVersionRun_525a {
  strings:
    $key_525a = { 01 35 [2] 25 3b [2] 0e 17 [2] 20 35 [2] 34 2e [2] 3b 34 [2] 25 29 [2] 27 28 [2] 3c 2e [2] 20 29 [2] 3c 06 }

  condition:
    any of them
}