rule TTP_XOR_QUAD_CurrentVersionRun_2c4d {
  strings:
    $key_2c4d = { 7f 22 [2] 5b 2c [2] 70 00 [2] 5e 22 [2] 4a 39 [2] 45 23 [2] 5b 3e [2] 59 3f [2] 42 39 [2] 5e 3e [2] 42 11 }

  condition:
    any of them
}