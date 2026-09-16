rule TTP_XOR_QUAD_CurrentVersionRun_2c6d {
  strings:
    $key_2c6d = { 7f 02 [2] 5b 0c [2] 70 20 [2] 5e 02 [2] 4a 19 [2] 45 03 [2] 5b 1e [2] 59 1f [2] 42 19 [2] 5e 1e [2] 42 31 }

  condition:
    any of them
}