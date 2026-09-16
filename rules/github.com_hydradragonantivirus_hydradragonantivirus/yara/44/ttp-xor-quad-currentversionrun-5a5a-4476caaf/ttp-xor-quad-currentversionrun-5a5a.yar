rule TTP_XOR_QUAD_CurrentVersionRun_5a5a {
  strings:
    $key_5a5a = { 09 35 [2] 2d 3b [2] 06 17 [2] 28 35 [2] 3c 2e [2] 33 34 [2] 2d 29 [2] 2f 28 [2] 34 2e [2] 28 29 [2] 34 06 }

  condition:
    any of them
}