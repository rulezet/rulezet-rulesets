rule TTP_XOR_QUAD_CurrentVersionRun_2c78 {
  strings:
    $key_2c78 = { 7f 17 [2] 5b 19 [2] 70 35 [2] 5e 17 [2] 4a 0c [2] 45 16 [2] 5b 0b [2] 59 0a [2] 42 0c [2] 5e 0b [2] 42 24 }

  condition:
    any of them
}