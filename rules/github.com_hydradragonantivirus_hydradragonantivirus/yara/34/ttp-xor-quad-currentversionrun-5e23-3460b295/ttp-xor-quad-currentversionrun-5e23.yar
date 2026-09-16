rule TTP_XOR_QUAD_CurrentVersionRun_5e23 {
  strings:
    $key_5e23 = { 0d 4c [2] 29 42 [2] 02 6e [2] 2c 4c [2] 38 57 [2] 37 4d [2] 29 50 [2] 2b 51 [2] 30 57 [2] 2c 50 [2] 30 7f }

  condition:
    any of them
}