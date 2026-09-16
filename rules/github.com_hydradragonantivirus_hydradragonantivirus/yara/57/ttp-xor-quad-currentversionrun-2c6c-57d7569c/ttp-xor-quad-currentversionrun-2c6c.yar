rule TTP_XOR_QUAD_CurrentVersionRun_2c6c {
  strings:
    $key_2c6c = { 7f 03 [2] 5b 0d [2] 70 21 [2] 5e 03 [2] 4a 18 [2] 45 02 [2] 5b 1f [2] 59 1e [2] 42 18 [2] 5e 1f [2] 42 30 }

  condition:
    any of them
}