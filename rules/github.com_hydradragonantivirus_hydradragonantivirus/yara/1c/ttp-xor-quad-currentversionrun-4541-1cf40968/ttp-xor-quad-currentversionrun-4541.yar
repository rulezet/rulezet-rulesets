rule TTP_XOR_QUAD_CurrentVersionRun_4541 {
  strings:
    $key_4541 = { 16 2e [2] 32 20 [2] 19 0c [2] 37 2e [2] 23 35 [2] 2c 2f [2] 32 32 [2] 30 33 [2] 2b 35 [2] 37 32 [2] 2b 1d }

  condition:
    any of them
}