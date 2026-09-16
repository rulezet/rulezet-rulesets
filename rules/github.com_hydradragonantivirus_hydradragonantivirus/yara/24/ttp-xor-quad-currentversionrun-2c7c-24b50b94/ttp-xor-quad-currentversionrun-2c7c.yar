rule TTP_XOR_QUAD_CurrentVersionRun_2c7c {
  strings:
    $key_2c7c = { 7f 13 [2] 5b 1d [2] 70 31 [2] 5e 13 [2] 4a 08 [2] 45 12 [2] 5b 0f [2] 59 0e [2] 42 08 [2] 5e 0f [2] 42 20 }

  condition:
    any of them
}