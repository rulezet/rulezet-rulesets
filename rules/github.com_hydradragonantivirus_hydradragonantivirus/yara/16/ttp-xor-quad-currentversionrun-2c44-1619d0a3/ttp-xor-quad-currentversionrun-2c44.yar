rule TTP_XOR_QUAD_CurrentVersionRun_2c44 {
  strings:
    $key_2c44 = { 7f 2b [2] 5b 25 [2] 70 09 [2] 5e 2b [2] 4a 30 [2] 45 2a [2] 5b 37 [2] 59 36 [2] 42 30 [2] 5e 37 [2] 42 18 }

  condition:
    any of them
}