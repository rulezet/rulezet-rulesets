rule TTP_XOR_QUAD_CurrentVersionRun_706d {
  strings:
    $key_706d = { 23 02 [2] 07 0c [2] 2c 20 [2] 02 02 [2] 16 19 [2] 19 03 [2] 07 1e [2] 05 1f [2] 1e 19 [2] 02 1e [2] 1e 31 }

  condition:
    any of them
}