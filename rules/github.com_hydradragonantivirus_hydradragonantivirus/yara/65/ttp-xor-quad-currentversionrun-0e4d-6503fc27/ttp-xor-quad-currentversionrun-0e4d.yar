rule TTP_XOR_QUAD_CurrentVersionRun_0e4d {
  strings:
    $key_0e4d = { 5d 22 [2] 79 2c [2] 52 00 [2] 7c 22 [2] 68 39 [2] 67 23 [2] 79 3e [2] 7b 3f [2] 60 39 [2] 7c 3e [2] 60 11 }

  condition:
    any of them
}