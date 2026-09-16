rule TTP_XOR_QUAD_CurrentVersionRun_2c1b {
  strings:
    $key_2c1b = { 7f 74 [2] 5b 7a [2] 70 56 [2] 5e 74 [2] 4a 6f [2] 45 75 [2] 5b 68 [2] 59 69 [2] 42 6f [2] 5e 68 [2] 42 47 }

  condition:
    any of them
}