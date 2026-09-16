rule TTP_XOR_QUAD_CurrentVersionRun_706c {
  strings:
    $key_706c = { 23 03 [2] 07 0d [2] 2c 21 [2] 02 03 [2] 16 18 [2] 19 02 [2] 07 1f [2] 05 1e [2] 1e 18 [2] 02 1f [2] 1e 30 }

  condition:
    any of them
}