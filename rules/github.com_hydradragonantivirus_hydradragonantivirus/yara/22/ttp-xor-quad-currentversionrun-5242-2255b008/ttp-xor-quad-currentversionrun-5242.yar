rule TTP_XOR_QUAD_CurrentVersionRun_5242 {
  strings:
    $key_5242 = { 01 2d [2] 25 23 [2] 0e 0f [2] 20 2d [2] 34 36 [2] 3b 2c [2] 25 31 [2] 27 30 [2] 3c 36 [2] 20 31 [2] 3c 1e }

  condition:
    any of them
}