rule TTP_XOR_QUAD_CurrentVersionRun_7f5a {
  strings:
    $key_7f5a = { 2c 35 [2] 08 3b [2] 23 17 [2] 0d 35 [2] 19 2e [2] 16 34 [2] 08 29 [2] 0a 28 [2] 11 2e [2] 0d 29 [2] 11 06 }

  condition:
    any of them
}