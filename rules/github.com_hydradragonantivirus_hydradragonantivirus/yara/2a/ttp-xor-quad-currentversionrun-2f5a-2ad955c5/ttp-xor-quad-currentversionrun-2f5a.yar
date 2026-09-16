rule TTP_XOR_QUAD_CurrentVersionRun_2f5a {
  strings:
    $key_2f5a = { 7c 35 [2] 58 3b [2] 73 17 [2] 5d 35 [2] 49 2e [2] 46 34 [2] 58 29 [2] 5a 28 [2] 41 2e [2] 5d 29 [2] 41 06 }

  condition:
    any of them
}