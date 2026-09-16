rule TTP_XOR_QUAD_CurrentVersionRun_2c0a {
  strings:
    $key_2c0a = { 7f 65 [2] 5b 6b [2] 70 47 [2] 5e 65 [2] 4a 7e [2] 45 64 [2] 5b 79 [2] 59 78 [2] 42 7e [2] 5e 79 [2] 42 56 }

  condition:
    any of them
}