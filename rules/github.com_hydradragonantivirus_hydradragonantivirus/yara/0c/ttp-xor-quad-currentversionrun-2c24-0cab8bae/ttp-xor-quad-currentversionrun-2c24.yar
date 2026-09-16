rule TTP_XOR_QUAD_CurrentVersionRun_2c24 {
  strings:
    $key_2c24 = { 7f 4b [2] 5b 45 [2] 70 69 [2] 5e 4b [2] 4a 50 [2] 45 4a [2] 5b 57 [2] 59 56 [2] 42 50 [2] 5e 57 [2] 42 78 }

  condition:
    any of them
}