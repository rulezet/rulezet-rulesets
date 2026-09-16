rule TTP_XOR_QUAD_CurrentVersionRun_7b2c {
  strings:
    $key_7b2c = { 28 43 [2] 0c 4d [2] 27 61 [2] 09 43 [2] 1d 58 [2] 12 42 [2] 0c 5f [2] 0e 5e [2] 15 58 [2] 09 5f [2] 15 70 }

  condition:
    any of them
}