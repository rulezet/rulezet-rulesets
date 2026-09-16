rule TTP_XOR_QUAD_CurrentVersionRun_4c5d {
  strings:
    $key_4c5d = { 1f 32 [2] 3b 3c [2] 10 10 [2] 3e 32 [2] 2a 29 [2] 25 33 [2] 3b 2e [2] 39 2f [2] 22 29 [2] 3e 2e [2] 22 01 }

  condition:
    any of them
}