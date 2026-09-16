rule TTP_XOR_QUAD_CurrentVersionRun_2c45 {
  strings:
    $key_2c45 = { 7f 2a [2] 5b 24 [2] 70 08 [2] 5e 2a [2] 4a 31 [2] 45 2b [2] 5b 36 [2] 59 37 [2] 42 31 [2] 5e 36 [2] 42 19 }

  condition:
    any of them
}