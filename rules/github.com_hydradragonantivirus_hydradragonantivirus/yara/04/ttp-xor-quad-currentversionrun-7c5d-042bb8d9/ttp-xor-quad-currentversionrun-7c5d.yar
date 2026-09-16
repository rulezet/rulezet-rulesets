rule TTP_XOR_QUAD_CurrentVersionRun_7c5d {
  strings:
    $key_7c5d = { 2f 32 [2] 0b 3c [2] 20 10 [2] 0e 32 [2] 1a 29 [2] 15 33 [2] 0b 2e [2] 09 2f [2] 12 29 [2] 0e 2e [2] 12 01 }

  condition:
    any of them
}