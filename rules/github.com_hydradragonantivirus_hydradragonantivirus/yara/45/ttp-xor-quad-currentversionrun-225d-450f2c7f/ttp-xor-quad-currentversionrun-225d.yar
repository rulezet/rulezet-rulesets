rule TTP_XOR_QUAD_CurrentVersionRun_225d {
  strings:
    $key_225d = { 71 32 [2] 55 3c [2] 7e 10 [2] 50 32 [2] 44 29 [2] 4b 33 [2] 55 2e [2] 57 2f [2] 4c 29 [2] 50 2e [2] 4c 01 }

  condition:
    any of them
}