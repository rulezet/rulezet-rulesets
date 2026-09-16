rule TTP_XOR_QUAD_CurrentVersionRun_394d {
  strings:
    $key_394d = { 6a 22 [2] 4e 2c [2] 65 00 [2] 4b 22 [2] 5f 39 [2] 50 23 [2] 4e 3e [2] 4c 3f [2] 57 39 [2] 4b 3e [2] 57 11 }

  condition:
    any of them
}