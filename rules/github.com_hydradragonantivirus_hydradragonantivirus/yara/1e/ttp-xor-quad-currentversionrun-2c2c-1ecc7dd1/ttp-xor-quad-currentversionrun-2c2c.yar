rule TTP_XOR_QUAD_CurrentVersionRun_2c2c {
  strings:
    $key_2c2c = { 7f 43 [2] 5b 4d [2] 70 61 [2] 5e 43 [2] 4a 58 [2] 45 42 [2] 5b 5f [2] 59 5e [2] 42 58 [2] 5e 5f [2] 42 70 }

  condition:
    any of them
}