rule TTP_XOR_QUAD_CurrentVersionRun_7019 {
  strings:
    $key_7019 = { 23 76 [2] 07 78 [2] 2c 54 [2] 02 76 [2] 16 6d [2] 19 77 [2] 07 6a [2] 05 6b [2] 1e 6d [2] 02 6a [2] 1e 45 }

  condition:
    any of them
}