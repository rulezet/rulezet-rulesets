rule TTP_XOR_QUAD_CurrentVersionRun_6c4d {
  strings:
    $key_6c4d = { 3f 22 [2] 1b 2c [2] 30 00 [2] 1e 22 [2] 0a 39 [2] 05 23 [2] 1b 3e [2] 19 3f [2] 02 39 [2] 1e 3e [2] 02 11 }

  condition:
    any of them
}