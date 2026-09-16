rule TTP_XOR_QUAD_CurrentVersionRun_2c2a {
  strings:
    $key_2c2a = { 7f 45 [2] 5b 4b [2] 70 67 [2] 5e 45 [2] 4a 5e [2] 45 44 [2] 5b 59 [2] 59 58 [2] 42 5e [2] 5e 59 [2] 42 76 }

  condition:
    any of them
}