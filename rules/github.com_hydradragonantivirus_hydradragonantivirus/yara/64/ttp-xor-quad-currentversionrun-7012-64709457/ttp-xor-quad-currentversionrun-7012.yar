rule TTP_XOR_QUAD_CurrentVersionRun_7012 {
  strings:
    $key_7012 = { 23 7d [2] 07 73 [2] 2c 5f [2] 02 7d [2] 16 66 [2] 19 7c [2] 07 61 [2] 05 60 [2] 1e 66 [2] 02 61 [2] 1e 4e }

  condition:
    any of them
}