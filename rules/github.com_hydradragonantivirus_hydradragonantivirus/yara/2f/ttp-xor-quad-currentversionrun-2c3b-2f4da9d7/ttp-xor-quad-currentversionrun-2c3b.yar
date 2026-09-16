rule TTP_XOR_QUAD_CurrentVersionRun_2c3b {
  strings:
    $key_2c3b = { 7f 54 [2] 5b 5a [2] 70 76 [2] 5e 54 [2] 4a 4f [2] 45 55 [2] 5b 48 [2] 59 49 [2] 42 4f [2] 5e 48 [2] 42 67 }

  condition:
    any of them
}