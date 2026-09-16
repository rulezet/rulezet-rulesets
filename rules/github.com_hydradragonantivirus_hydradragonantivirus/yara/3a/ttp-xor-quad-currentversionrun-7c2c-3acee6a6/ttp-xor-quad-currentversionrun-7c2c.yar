rule TTP_XOR_QUAD_CurrentVersionRun_7c2c {
  strings:
    $key_7c2c = { 2f 43 [2] 0b 4d [2] 20 61 [2] 0e 43 [2] 1a 58 [2] 15 42 [2] 0b 5f [2] 09 5e [2] 12 58 [2] 0e 5f [2] 12 70 }

  condition:
    any of them
}