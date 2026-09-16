rule TTP_XOR_QUAD_CurrentVersionRun_402c {
  strings:
    $key_402c = { 13 43 [2] 37 4d [2] 1c 61 [2] 32 43 [2] 26 58 [2] 29 42 [2] 37 5f [2] 35 5e [2] 2e 58 [2] 32 5f [2] 2e 70 }

  condition:
    any of them
}