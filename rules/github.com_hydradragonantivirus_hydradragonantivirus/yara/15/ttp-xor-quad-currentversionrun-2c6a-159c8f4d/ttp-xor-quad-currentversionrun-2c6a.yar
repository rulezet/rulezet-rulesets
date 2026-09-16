rule TTP_XOR_QUAD_CurrentVersionRun_2c6a {
  strings:
    $key_2c6a = { 7f 05 [2] 5b 0b [2] 70 27 [2] 5e 05 [2] 4a 1e [2] 45 04 [2] 5b 19 [2] 59 18 [2] 42 1e [2] 5e 19 [2] 42 36 }

  condition:
    any of them
}