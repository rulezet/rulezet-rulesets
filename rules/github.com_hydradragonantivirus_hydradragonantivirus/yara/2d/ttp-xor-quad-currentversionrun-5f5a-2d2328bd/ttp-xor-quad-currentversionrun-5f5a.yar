rule TTP_XOR_QUAD_CurrentVersionRun_5f5a {
  strings:
    $key_5f5a = { 0c 35 [2] 28 3b [2] 03 17 [2] 2d 35 [2] 39 2e [2] 36 34 [2] 28 29 [2] 2a 28 [2] 31 2e [2] 2d 29 [2] 31 06 }

  condition:
    any of them
}