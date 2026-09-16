rule TTP_XOR_QUAD_CurrentVersionRun_7001 {
  strings:
    $key_7001 = { 23 6e [2] 07 60 [2] 2c 4c [2] 02 6e [2] 16 75 [2] 19 6f [2] 07 72 [2] 05 73 [2] 1e 75 [2] 02 72 [2] 1e 5d }

  condition:
    any of them
}