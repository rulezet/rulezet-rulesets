rule TTP_XOR_QUAD_CurrentVersionRun_5b6c {
  strings:
    $key_5b6c = { 08 03 [2] 2c 0d [2] 07 21 [2] 29 03 [2] 3d 18 [2] 32 02 [2] 2c 1f [2] 2e 1e [2] 35 18 [2] 29 1f [2] 35 30 }

  condition:
    any of them
}