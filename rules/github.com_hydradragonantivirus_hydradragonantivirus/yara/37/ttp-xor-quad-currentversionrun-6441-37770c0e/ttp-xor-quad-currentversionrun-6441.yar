rule TTP_XOR_QUAD_CurrentVersionRun_6441 {
  strings:
    $key_6441 = { 37 2e [2] 13 20 [2] 38 0c [2] 16 2e [2] 02 35 [2] 0d 2f [2] 13 32 [2] 11 33 [2] 0a 35 [2] 16 32 [2] 0a 1d }

  condition:
    any of them
}