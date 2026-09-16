rule TTP_XOR_QUAD_CurrentVersionRun_4d4d {
  strings:
    $key_4d4d = { 1e 22 [2] 3a 2c [2] 11 00 [2] 3f 22 [2] 2b 39 [2] 24 23 [2] 3a 3e [2] 38 3f [2] 23 39 [2] 3f 3e [2] 23 11 }

  condition:
    any of them
}