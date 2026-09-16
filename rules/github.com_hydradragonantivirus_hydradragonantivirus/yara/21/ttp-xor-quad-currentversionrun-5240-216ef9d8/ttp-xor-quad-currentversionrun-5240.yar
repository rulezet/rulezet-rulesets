rule TTP_XOR_QUAD_CurrentVersionRun_5240 {
  strings:
    $key_5240 = { 01 2f [2] 25 21 [2] 0e 0d [2] 20 2f [2] 34 34 [2] 3b 2e [2] 25 33 [2] 27 32 [2] 3c 34 [2] 20 33 [2] 3c 1c }

  condition:
    any of them
}