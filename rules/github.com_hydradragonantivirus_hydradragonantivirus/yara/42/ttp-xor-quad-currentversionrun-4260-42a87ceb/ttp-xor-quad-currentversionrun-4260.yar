rule TTP_XOR_QUAD_CurrentVersionRun_4260 {
  strings:
    $key_4260 = { 11 0f [2] 35 01 [2] 1e 2d [2] 30 0f [2] 24 14 [2] 2b 0e [2] 35 13 [2] 37 12 [2] 2c 14 [2] 30 13 [2] 2c 3c }

  condition:
    any of them
}