rule TTP_XOR_QUAD_CurrentVersionRun_7242 {
  strings:
    $key_7242 = { 21 2d [2] 05 23 [2] 2e 0f [2] 00 2d [2] 14 36 [2] 1b 2c [2] 05 31 [2] 07 30 [2] 1c 36 [2] 00 31 [2] 1c 1e }

  condition:
    any of them
}