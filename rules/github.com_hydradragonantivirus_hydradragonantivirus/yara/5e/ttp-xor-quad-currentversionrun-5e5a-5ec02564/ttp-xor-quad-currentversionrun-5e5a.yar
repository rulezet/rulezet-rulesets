rule TTP_XOR_QUAD_CurrentVersionRun_5e5a {
  strings:
    $key_5e5a = { 0d 35 [2] 29 3b [2] 02 17 [2] 2c 35 [2] 38 2e [2] 37 34 [2] 29 29 [2] 2b 28 [2] 30 2e [2] 2c 29 [2] 30 06 }

  condition:
    any of them
}