rule TTP_XOR_QUAD_CurrentVersionRun_1b5d {
  strings:
    $key_1b5d = { 48 32 [2] 6c 3c [2] 47 10 [2] 69 32 [2] 7d 29 [2] 72 33 [2] 6c 2e [2] 6e 2f [2] 75 29 [2] 69 2e [2] 75 01 }

  condition:
    any of them
}