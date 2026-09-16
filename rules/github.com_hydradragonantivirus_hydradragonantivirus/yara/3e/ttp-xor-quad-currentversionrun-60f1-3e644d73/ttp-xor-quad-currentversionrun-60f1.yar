rule TTP_XOR_QUAD_CurrentVersionRun_60f1 {
  strings:
    $key_60f1 = { 33 9e [2] 17 90 [2] 3c bc [2] 12 9e [2] 06 85 [2] 09 9f [2] 17 82 [2] 15 83 [2] 0e 85 [2] 12 82 [2] 0e ad }

  condition:
    any of them
}