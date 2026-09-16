rule TTP_XOR_QUAD_CurrentVersionRun_4241 {
  strings:
    $key_4241 = { 11 2e [2] 35 20 [2] 1e 0c [2] 30 2e [2] 24 35 [2] 2b 2f [2] 35 32 [2] 37 33 [2] 2c 35 [2] 30 32 [2] 2c 1d }

  condition:
    any of them
}