rule TTP_XOR_QUAD_CurrentVersionRun_2cfa {
  strings:
    $key_2cfa = { 7f 95 [2] 5b 9b [2] 70 b7 [2] 5e 95 [2] 4a 8e [2] 45 94 [2] 5b 89 [2] 59 88 [2] 42 8e [2] 5e 89 [2] 42 a6 }

  condition:
    any of them
}