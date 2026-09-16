rule TTP_XOR_QUAD_CurrentVersionRun_792a {
  strings:
    $key_792a = { 2a 45 [2] 0e 4b [2] 25 67 [2] 0b 45 [2] 1f 5e [2] 10 44 [2] 0e 59 [2] 0c 58 [2] 17 5e [2] 0b 59 [2] 17 76 }

  condition:
    any of them
}