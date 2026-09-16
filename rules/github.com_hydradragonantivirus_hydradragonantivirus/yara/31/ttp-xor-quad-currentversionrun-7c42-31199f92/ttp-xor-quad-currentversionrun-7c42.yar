rule TTP_XOR_QUAD_CurrentVersionRun_7c42 {
  strings:
    $key_7c42 = { 2f 2d [2] 0b 23 [2] 20 0f [2] 0e 2d [2] 1a 36 [2] 15 2c [2] 0b 31 [2] 09 30 [2] 12 36 [2] 0e 31 [2] 12 1e }

  condition:
    any of them
}