rule TTP_XOR_QUAD_CurrentVersionRun_7b5d {
  strings:
    $key_7b5d = { 28 32 [2] 0c 3c [2] 27 10 [2] 09 32 [2] 1d 29 [2] 12 33 [2] 0c 2e [2] 0e 2f [2] 15 29 [2] 09 2e [2] 15 01 }

  condition:
    any of them
}