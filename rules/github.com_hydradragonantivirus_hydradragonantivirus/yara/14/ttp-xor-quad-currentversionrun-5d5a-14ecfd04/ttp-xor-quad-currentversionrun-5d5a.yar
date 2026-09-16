rule TTP_XOR_QUAD_CurrentVersionRun_5d5a {
  strings:
    $key_5d5a = { 0e 35 [2] 2a 3b [2] 01 17 [2] 2f 35 [2] 3b 2e [2] 34 34 [2] 2a 29 [2] 28 28 [2] 33 2e [2] 2f 29 [2] 33 06 }

  condition:
    any of them
}