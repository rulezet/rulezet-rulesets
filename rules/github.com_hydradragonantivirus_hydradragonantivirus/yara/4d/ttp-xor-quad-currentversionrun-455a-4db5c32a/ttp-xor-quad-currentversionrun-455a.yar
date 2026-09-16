rule TTP_XOR_QUAD_CurrentVersionRun_455a {
  strings:
    $key_455a = { 16 35 [2] 32 3b [2] 19 17 [2] 37 35 [2] 23 2e [2] 2c 34 [2] 32 29 [2] 30 28 [2] 2b 2e [2] 37 29 [2] 2b 06 }

  condition:
    any of them
}