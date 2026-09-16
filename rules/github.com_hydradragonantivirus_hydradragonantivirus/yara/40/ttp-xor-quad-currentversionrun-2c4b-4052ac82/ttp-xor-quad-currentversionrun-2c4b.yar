rule TTP_XOR_QUAD_CurrentVersionRun_2c4b {
  strings:
    $key_2c4b = { 7f 24 [2] 5b 2a [2] 70 06 [2] 5e 24 [2] 4a 3f [2] 45 25 [2] 5b 38 [2] 59 39 [2] 42 3f [2] 5e 38 [2] 42 17 }

  condition:
    any of them
}