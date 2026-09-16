rule TTP_XOR_QUAD_CurrentVersionRun_4e5d {
  strings:
    $key_4e5d = { 1d 32 [2] 39 3c [2] 12 10 [2] 3c 32 [2] 28 29 [2] 27 33 [2] 39 2e [2] 3b 2f [2] 20 29 [2] 3c 2e [2] 20 01 }

  condition:
    any of them
}