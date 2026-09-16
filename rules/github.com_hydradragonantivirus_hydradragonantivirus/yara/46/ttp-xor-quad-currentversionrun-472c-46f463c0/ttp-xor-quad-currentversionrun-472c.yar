rule TTP_XOR_QUAD_CurrentVersionRun_472c {
  strings:
    $key_472c = { 14 43 [2] 30 4d [2] 1b 61 [2] 35 43 [2] 21 58 [2] 2e 42 [2] 30 5f [2] 32 5e [2] 29 58 [2] 35 5f [2] 29 70 }

  condition:
    any of them
}