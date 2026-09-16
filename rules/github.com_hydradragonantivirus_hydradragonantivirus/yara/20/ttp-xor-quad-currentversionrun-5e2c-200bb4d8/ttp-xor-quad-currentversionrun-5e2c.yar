rule TTP_XOR_QUAD_CurrentVersionRun_5e2c {
  strings:
    $key_5e2c = { 0d 43 [2] 29 4d [2] 02 61 [2] 2c 43 [2] 38 58 [2] 37 42 [2] 29 5f [2] 2b 5e [2] 30 58 [2] 2c 5f [2] 30 70 }

  condition:
    any of them
}