rule TTP_XOR_QUAD_CurrentVersionRun_2c25 {
  strings:
    $key_2c25 = { 7f 4a [2] 5b 44 [2] 70 68 [2] 5e 4a [2] 4a 51 [2] 45 4b [2] 5b 56 [2] 59 57 [2] 42 51 [2] 5e 56 [2] 42 79 }

  condition:
    any of them
}