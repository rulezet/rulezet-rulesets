rule TTP_XOR_QUAD_CurrentVersionRun_2c7b {
  strings:
    $key_2c7b = { 7f 14 [2] 5b 1a [2] 70 36 [2] 5e 14 [2] 4a 0f [2] 45 15 [2] 5b 08 [2] 59 09 [2] 42 0f [2] 5e 08 [2] 42 27 }

  condition:
    any of them
}