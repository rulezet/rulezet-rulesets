rule TTP_XOR_QUAD_CurrentVersionRun_4571 {
  strings:
    $key_4571 = { 16 1e [2] 32 10 [2] 19 3c [2] 37 1e [2] 23 05 [2] 2c 1f [2] 32 02 [2] 30 03 [2] 2b 05 [2] 37 02 [2] 2b 2d }

  condition:
    any of them
}