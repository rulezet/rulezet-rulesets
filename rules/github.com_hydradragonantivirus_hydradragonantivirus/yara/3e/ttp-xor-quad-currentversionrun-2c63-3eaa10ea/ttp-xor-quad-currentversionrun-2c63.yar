rule TTP_XOR_QUAD_CurrentVersionRun_2c63 {
  strings:
    $key_2c63 = { 7f 0c [2] 5b 02 [2] 70 2e [2] 5e 0c [2] 4a 17 [2] 45 0d [2] 5b 10 [2] 59 11 [2] 42 17 [2] 5e 10 [2] 42 3f }

  condition:
    any of them
}