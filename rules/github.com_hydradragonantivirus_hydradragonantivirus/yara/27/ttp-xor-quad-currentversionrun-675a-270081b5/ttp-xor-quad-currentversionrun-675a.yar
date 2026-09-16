rule TTP_XOR_QUAD_CurrentVersionRun_675a {
  strings:
    $key_675a = { 34 35 [2] 10 3b [2] 3b 17 [2] 15 35 [2] 01 2e [2] 0e 34 [2] 10 29 [2] 12 28 [2] 09 2e [2] 15 29 [2] 09 06 }

  condition:
    any of them
}