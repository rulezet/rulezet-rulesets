rule TTP_XOR_QUAD_CurrentVersionRun_7000 {
  strings:
    $key_7000 = { 23 6f [2] 07 61 [2] 2c 4d [2] 02 6f [2] 16 74 [2] 19 6e [2] 07 73 [2] 05 72 [2] 1e 74 [2] 02 73 [2] 1e 5c }

  condition:
    any of them
}