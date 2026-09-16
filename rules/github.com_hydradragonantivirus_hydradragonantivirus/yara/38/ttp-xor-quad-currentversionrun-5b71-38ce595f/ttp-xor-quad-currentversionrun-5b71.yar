rule TTP_XOR_QUAD_CurrentVersionRun_5b71 {
  strings:
    $key_5b71 = { 08 1e [2] 2c 10 [2] 07 3c [2] 29 1e [2] 3d 05 [2] 32 1f [2] 2c 02 [2] 2e 03 [2] 35 05 [2] 29 02 [2] 35 2d }

  condition:
    any of them
}