rule TTP_XOR_QUAD_CurrentVersionRun_2c07 {
  strings:
    $key_2c07 = { 7f 68 [2] 5b 66 [2] 70 4a [2] 5e 68 [2] 4a 73 [2] 45 69 [2] 5b 74 [2] 59 75 [2] 42 73 [2] 5e 74 [2] 42 5b }

  condition:
    any of them
}