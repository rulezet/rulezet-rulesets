rule TTP_XOR_QUAD_CurrentVersionRun_79fa {
  strings:
    $key_79fa = { 2a 95 [2] 0e 9b [2] 25 b7 [2] 0b 95 [2] 1f 8e [2] 10 94 [2] 0e 89 [2] 0c 88 [2] 17 8e [2] 0b 89 [2] 17 a6 }

  condition:
    any of them
}