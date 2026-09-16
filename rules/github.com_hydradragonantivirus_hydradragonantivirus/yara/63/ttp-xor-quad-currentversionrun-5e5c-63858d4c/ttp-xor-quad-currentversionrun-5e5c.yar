rule TTP_XOR_QUAD_CurrentVersionRun_5e5c {
  strings:
    $key_5e5c = { 0d 33 [2] 29 3d [2] 02 11 [2] 2c 33 [2] 38 28 [2] 37 32 [2] 29 2f [2] 2b 2e [2] 30 28 [2] 2c 2f [2] 30 00 }

  condition:
    any of them
}