rule TTP_XOR_QUAD_CurrentVersionRun_5b5c {
  strings:
    $key_5b5c = { 08 33 [2] 2c 3d [2] 07 11 [2] 29 33 [2] 3d 28 [2] 32 32 [2] 2c 2f [2] 2e 2e [2] 35 28 [2] 29 2f [2] 35 00 }

  condition:
    any of them
}