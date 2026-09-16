rule TTP_XOR_QUAD_CurrentVersionRun_554d {
  strings:
    $key_554d = { 06 22 [2] 22 2c [2] 09 00 [2] 27 22 [2] 33 39 [2] 3c 23 [2] 22 3e [2] 20 3f [2] 3b 39 [2] 27 3e [2] 3b 11 }

  condition:
    any of them
}