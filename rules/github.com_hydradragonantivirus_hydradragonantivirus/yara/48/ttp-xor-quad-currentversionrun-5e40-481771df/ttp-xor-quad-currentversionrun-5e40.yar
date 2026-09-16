rule TTP_XOR_QUAD_CurrentVersionRun_5e40 {
  strings:
    $key_5e40 = { 0d 2f [2] 29 21 [2] 02 0d [2] 2c 2f [2] 38 34 [2] 37 2e [2] 29 33 [2] 2b 32 [2] 30 34 [2] 2c 33 [2] 30 1c }

  condition:
    any of them
}