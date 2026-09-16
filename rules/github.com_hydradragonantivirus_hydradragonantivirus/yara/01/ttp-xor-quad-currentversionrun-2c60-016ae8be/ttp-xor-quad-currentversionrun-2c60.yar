rule TTP_XOR_QUAD_CurrentVersionRun_2c60 {
  strings:
    $key_2c60 = { 7f 0f [2] 5b 01 [2] 70 2d [2] 5e 0f [2] 4a 14 [2] 45 0e [2] 5b 13 [2] 59 12 [2] 42 14 [2] 5e 13 [2] 42 3c }

  condition:
    any of them
}