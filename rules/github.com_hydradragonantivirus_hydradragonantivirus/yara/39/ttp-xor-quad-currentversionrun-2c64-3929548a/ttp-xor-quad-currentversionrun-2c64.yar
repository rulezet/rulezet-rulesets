rule TTP_XOR_QUAD_CurrentVersionRun_2c64 {
  strings:
    $key_2c64 = { 7f 0b [2] 5b 05 [2] 70 29 [2] 5e 0b [2] 4a 10 [2] 45 0a [2] 5b 17 [2] 59 16 [2] 42 10 [2] 5e 17 [2] 42 38 }

  condition:
    any of them
}