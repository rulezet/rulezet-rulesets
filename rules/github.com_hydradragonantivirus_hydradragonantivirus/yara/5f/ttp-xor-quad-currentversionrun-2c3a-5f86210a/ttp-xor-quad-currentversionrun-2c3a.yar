rule TTP_XOR_QUAD_CurrentVersionRun_2c3a {
  strings:
    $key_2c3a = { 7f 55 [2] 5b 5b [2] 70 77 [2] 5e 55 [2] 4a 4e [2] 45 54 [2] 5b 49 [2] 59 48 [2] 42 4e [2] 5e 49 [2] 42 66 }

  condition:
    any of them
}