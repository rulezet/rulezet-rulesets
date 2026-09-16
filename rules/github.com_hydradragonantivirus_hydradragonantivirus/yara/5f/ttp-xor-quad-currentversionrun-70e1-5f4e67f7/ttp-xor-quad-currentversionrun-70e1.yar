rule TTP_XOR_QUAD_CurrentVersionRun_70e1 {
  strings:
    $key_70e1 = { 23 8e [2] 07 80 [2] 2c ac [2] 02 8e [2] 16 95 [2] 19 8f [2] 07 92 [2] 05 93 [2] 1e 95 [2] 02 92 [2] 1e bd }

  condition:
    any of them
}