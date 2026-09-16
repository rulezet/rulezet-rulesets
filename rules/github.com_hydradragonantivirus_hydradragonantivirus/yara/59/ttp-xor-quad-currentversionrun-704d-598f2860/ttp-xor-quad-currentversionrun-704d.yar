rule TTP_XOR_QUAD_CurrentVersionRun_704d {
  strings:
    $key_704d = { 23 22 [2] 07 2c [2] 2c 00 [2] 02 22 [2] 16 39 [2] 19 23 [2] 07 3e [2] 05 3f [2] 1e 39 [2] 02 3e [2] 1e 11 }

  condition:
    any of them
}