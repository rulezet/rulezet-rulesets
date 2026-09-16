rule TTP_XOR_QUAD_CurrentVersionRun_2c79 {
  strings:
    $key_2c79 = { 7f 16 [2] 5b 18 [2] 70 34 [2] 5e 16 [2] 4a 0d [2] 45 17 [2] 5b 0a [2] 59 0b [2] 42 0d [2] 5e 0a [2] 42 25 }

  condition:
    any of them
}