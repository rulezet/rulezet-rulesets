rule TTP_XOR_QUAD_CurrentVersionRun_6040 {
  strings:
    $key_6040 = { 33 2f [2] 17 21 [2] 3c 0d [2] 12 2f [2] 06 34 [2] 09 2e [2] 17 33 [2] 15 32 [2] 0e 34 [2] 12 33 [2] 0e 1c }

  condition:
    any of them
}