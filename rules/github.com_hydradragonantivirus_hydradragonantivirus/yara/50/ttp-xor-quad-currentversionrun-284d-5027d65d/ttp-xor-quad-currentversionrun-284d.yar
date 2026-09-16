rule TTP_XOR_QUAD_CurrentVersionRun_284d {
  strings:
    $key_284d = { 7b 22 [2] 5f 2c [2] 74 00 [2] 5a 22 [2] 4e 39 [2] 41 23 [2] 5f 3e [2] 5d 3f [2] 46 39 [2] 5a 3e [2] 46 11 }

  condition:
    any of them
}