rule TTP_XOR_QUAD_CurrentVersionRun_7040 {
  strings:
    $key_7040 = { 23 2f [2] 07 21 [2] 2c 0d [2] 02 2f [2] 16 34 [2] 19 2e [2] 07 33 [2] 05 32 [2] 1e 34 [2] 02 33 [2] 1e 1c }

  condition:
    any of them
}