rule TTP_XOR_QUAD_CurrentVersionRun_2c50 {
  strings:
    $key_2c50 = { 7f 3f [2] 5b 31 [2] 70 1d [2] 5e 3f [2] 4a 24 [2] 45 3e [2] 5b 23 [2] 59 22 [2] 42 24 [2] 5e 23 [2] 42 0c }

  condition:
    any of them
}