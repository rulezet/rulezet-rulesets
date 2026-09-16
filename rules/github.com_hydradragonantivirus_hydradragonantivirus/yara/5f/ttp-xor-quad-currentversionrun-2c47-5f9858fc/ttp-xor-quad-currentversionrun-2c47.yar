rule TTP_XOR_QUAD_CurrentVersionRun_2c47 {
  strings:
    $key_2c47 = { 7f 28 [2] 5b 26 [2] 70 0a [2] 5e 28 [2] 4a 33 [2] 45 29 [2] 5b 34 [2] 59 35 [2] 42 33 [2] 5e 34 [2] 42 1b }

  condition:
    any of them
}