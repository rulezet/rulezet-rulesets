rule TTP_XOR_QUAD_CurrentVersionRun_2c74 {
  strings:
    $key_2c74 = { 7f 1b [2] 5b 15 [2] 70 39 [2] 5e 1b [2] 4a 00 [2] 45 1a [2] 5b 07 [2] 59 06 [2] 42 00 [2] 5e 07 [2] 42 28 }

  condition:
    any of them
}