rule TTP_XOR_QUAD_CurrentVersionRun_2c5b {
  strings:
    $key_2c5b = { 7f 34 [2] 5b 3a [2] 70 16 [2] 5e 34 [2] 4a 2f [2] 45 35 [2] 5b 28 [2] 59 29 [2] 42 2f [2] 5e 28 [2] 42 07 }

  condition:
    any of them
}