rule TTP_XOR_QUAD_CurrentVersionRun_5e41 {
  strings:
    $key_5e41 = { 0d 2e [2] 29 20 [2] 02 0c [2] 2c 2e [2] 38 35 [2] 37 2f [2] 29 32 [2] 2b 33 [2] 30 35 [2] 2c 32 [2] 30 1d }

  condition:
    any of them
}