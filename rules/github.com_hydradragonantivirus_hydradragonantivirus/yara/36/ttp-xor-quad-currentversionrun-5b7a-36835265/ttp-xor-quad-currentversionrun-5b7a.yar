rule TTP_XOR_QUAD_CurrentVersionRun_5b7a {
  strings:
    $key_5b7a = { 08 15 [2] 2c 1b [2] 07 37 [2] 29 15 [2] 3d 0e [2] 32 14 [2] 2c 09 [2] 2e 08 [2] 35 0e [2] 29 09 [2] 35 26 }

  condition:
    any of them
}