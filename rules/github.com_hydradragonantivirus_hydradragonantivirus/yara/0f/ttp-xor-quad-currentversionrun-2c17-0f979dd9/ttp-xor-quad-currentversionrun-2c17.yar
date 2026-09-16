rule TTP_XOR_QUAD_CurrentVersionRun_2c17 {
  strings:
    $key_2c17 = { 7f 78 [2] 5b 76 [2] 70 5a [2] 5e 78 [2] 4a 63 [2] 45 79 [2] 5b 64 [2] 59 65 [2] 42 63 [2] 5e 64 [2] 42 4b }

  condition:
    any of them
}