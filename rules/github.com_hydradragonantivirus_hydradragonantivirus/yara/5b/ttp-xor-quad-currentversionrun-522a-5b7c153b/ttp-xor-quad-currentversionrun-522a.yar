rule TTP_XOR_QUAD_CurrentVersionRun_522a {
  strings:
    $key_522a = { 01 45 [2] 25 4b [2] 0e 67 [2] 20 45 [2] 34 5e [2] 3b 44 [2] 25 59 [2] 27 58 [2] 3c 5e [2] 20 59 [2] 3c 76 }

  condition:
    any of them
}