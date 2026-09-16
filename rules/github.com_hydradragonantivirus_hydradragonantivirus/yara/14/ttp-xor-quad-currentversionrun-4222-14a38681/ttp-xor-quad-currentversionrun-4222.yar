rule TTP_XOR_QUAD_CurrentVersionRun_4222 {
  strings:
    $key_4222 = { 11 4d [2] 35 43 [2] 1e 6f [2] 30 4d [2] 24 56 [2] 2b 4c [2] 35 51 [2] 37 50 [2] 2c 56 [2] 30 51 [2] 2c 7e }

  condition:
    any of them
}