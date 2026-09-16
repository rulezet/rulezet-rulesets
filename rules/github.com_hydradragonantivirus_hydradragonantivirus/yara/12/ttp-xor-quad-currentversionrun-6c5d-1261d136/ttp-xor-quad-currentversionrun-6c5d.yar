rule TTP_XOR_QUAD_CurrentVersionRun_6c5d {
  strings:
    $key_6c5d = { 3f 32 [2] 1b 3c [2] 30 10 [2] 1e 32 [2] 0a 29 [2] 05 33 [2] 1b 2e [2] 19 2f [2] 02 29 [2] 1e 2e [2] 02 01 }

  condition:
    any of them
}