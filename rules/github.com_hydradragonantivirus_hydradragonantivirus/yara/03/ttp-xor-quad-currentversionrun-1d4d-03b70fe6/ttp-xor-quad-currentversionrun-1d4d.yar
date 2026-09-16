rule TTP_XOR_QUAD_CurrentVersionRun_1d4d {
  strings:
    $key_1d4d = { 4e 22 [2] 6a 2c [2] 41 00 [2] 6f 22 [2] 7b 39 [2] 74 23 [2] 6a 3e [2] 68 3f [2] 73 39 [2] 6f 3e [2] 73 11 }

  condition:
    any of them
}