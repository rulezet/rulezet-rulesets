rule TTP_XOR_QUAD_CurrentVersionRun_5e4c {
  strings:
    $key_5e4c = { 0d 23 [2] 29 2d [2] 02 01 [2] 2c 23 [2] 38 38 [2] 37 22 [2] 29 3f [2] 2b 3e [2] 30 38 [2] 2c 3f [2] 30 10 }

  condition:
    any of them
}