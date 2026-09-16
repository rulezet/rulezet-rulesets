rule TTP_XOR_QUAD_CurrentVersionRun_70f1 {
  strings:
    $key_70f1 = { 23 9e [2] 07 90 [2] 2c bc [2] 02 9e [2] 16 85 [2] 19 9f [2] 07 82 [2] 05 83 [2] 1e 85 [2] 02 82 [2] 1e ad }

  condition:
    any of them
}