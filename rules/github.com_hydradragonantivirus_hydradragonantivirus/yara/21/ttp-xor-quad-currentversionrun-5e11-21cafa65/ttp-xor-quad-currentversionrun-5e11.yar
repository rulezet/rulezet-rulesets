rule TTP_XOR_QUAD_CurrentVersionRun_5e11 {
  strings:
    $key_5e11 = { 0d 7e [2] 29 70 [2] 02 5c [2] 2c 7e [2] 38 65 [2] 37 7f [2] 29 62 [2] 2b 63 [2] 30 65 [2] 2c 62 [2] 30 4d }

  condition:
    any of them
}