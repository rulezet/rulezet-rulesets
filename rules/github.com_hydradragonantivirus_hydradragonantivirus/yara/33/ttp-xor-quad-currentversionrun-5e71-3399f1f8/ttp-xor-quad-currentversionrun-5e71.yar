rule TTP_XOR_QUAD_CurrentVersionRun_5e71 {
  strings:
    $key_5e71 = { 0d 1e [2] 29 10 [2] 02 3c [2] 2c 1e [2] 38 05 [2] 37 1f [2] 29 02 [2] 2b 03 [2] 30 05 [2] 2c 02 [2] 30 2d }

  condition:
    any of them
}