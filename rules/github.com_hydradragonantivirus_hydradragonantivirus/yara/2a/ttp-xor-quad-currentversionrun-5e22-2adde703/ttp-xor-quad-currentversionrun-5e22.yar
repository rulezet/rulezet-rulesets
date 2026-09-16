rule TTP_XOR_QUAD_CurrentVersionRun_5e22 {
  strings:
    $key_5e22 = { 0d 4d [2] 29 43 [2] 02 6f [2] 2c 4d [2] 38 56 [2] 37 4c [2] 29 51 [2] 2b 50 [2] 30 56 [2] 2c 51 [2] 30 7e }

  condition:
    any of them
}