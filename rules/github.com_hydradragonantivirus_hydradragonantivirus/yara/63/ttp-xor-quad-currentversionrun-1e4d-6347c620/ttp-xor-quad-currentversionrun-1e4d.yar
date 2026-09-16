rule TTP_XOR_QUAD_CurrentVersionRun_1e4d {
  strings:
    $key_1e4d = { 4d 22 [2] 69 2c [2] 42 00 [2] 6c 22 [2] 78 39 [2] 77 23 [2] 69 3e [2] 6b 3f [2] 70 39 [2] 6c 3e [2] 70 11 }

  condition:
    any of them
}