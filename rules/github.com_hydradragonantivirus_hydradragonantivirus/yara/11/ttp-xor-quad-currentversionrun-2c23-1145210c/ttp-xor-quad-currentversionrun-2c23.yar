rule TTP_XOR_QUAD_CurrentVersionRun_2c23 {
  strings:
    $key_2c23 = { 7f 4c [2] 5b 42 [2] 70 6e [2] 5e 4c [2] 4a 57 [2] 45 4d [2] 5b 50 [2] 59 51 [2] 42 57 [2] 5e 50 [2] 42 7f }

  condition:
    any of them
}