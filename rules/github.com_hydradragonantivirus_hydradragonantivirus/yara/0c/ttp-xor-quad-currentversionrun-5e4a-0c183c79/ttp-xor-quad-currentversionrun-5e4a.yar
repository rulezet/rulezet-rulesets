rule TTP_XOR_QUAD_CurrentVersionRun_5e4a {
  strings:
    $key_5e4a = { 0d 25 [2] 29 2b [2] 02 07 [2] 2c 25 [2] 38 3e [2] 37 24 [2] 29 39 [2] 2b 38 [2] 30 3e [2] 2c 39 [2] 30 16 }

  condition:
    any of them
}