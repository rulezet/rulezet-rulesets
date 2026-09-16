rule TTP_XOR_QUAD_CurrentVersionRun_675d {
  strings:
    $key_675d = { 34 32 [2] 10 3c [2] 3b 10 [2] 15 32 [2] 01 29 [2] 0e 33 [2] 10 2e [2] 12 2f [2] 09 29 [2] 15 2e [2] 09 01 }

  condition:
    any of them
}