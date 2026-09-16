rule TTP_XOR_QUAD_CurrentVersionRun_1d2c {
  strings:
    $key_1d2c = { 4e 43 [2] 6a 4d [2] 41 61 [2] 6f 43 [2] 7b 58 [2] 74 42 [2] 6a 5f [2] 68 5e [2] 73 58 [2] 6f 5f [2] 73 70 }

  condition:
    any of them
}