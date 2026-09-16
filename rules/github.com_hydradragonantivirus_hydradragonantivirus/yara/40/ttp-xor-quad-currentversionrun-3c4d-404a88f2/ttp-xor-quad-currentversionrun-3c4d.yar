rule TTP_XOR_QUAD_CurrentVersionRun_3c4d {
  strings:
    $key_3c4d = { 6f 22 [2] 4b 2c [2] 60 00 [2] 4e 22 [2] 5a 39 [2] 55 23 [2] 4b 3e [2] 49 3f [2] 52 39 [2] 4e 3e [2] 52 11 }

  condition:
    any of them
}