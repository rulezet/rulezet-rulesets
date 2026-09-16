rule TTP_XOR_QUAD_CurrentVersionRun_7f2c {
  strings:
    $key_7f2c = { 2c 43 [2] 08 4d [2] 23 61 [2] 0d 43 [2] 19 58 [2] 16 42 [2] 08 5f [2] 0a 5e [2] 11 58 [2] 0d 5f [2] 11 70 }

  condition:
    any of them
}