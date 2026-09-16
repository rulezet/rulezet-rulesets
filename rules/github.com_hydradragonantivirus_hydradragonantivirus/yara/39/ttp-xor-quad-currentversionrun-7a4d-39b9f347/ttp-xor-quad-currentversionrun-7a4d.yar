rule TTP_XOR_QUAD_CurrentVersionRun_7a4d {
  strings:
    $key_7a4d = { 29 22 [2] 0d 2c [2] 26 00 [2] 08 22 [2] 1c 39 [2] 13 23 [2] 0d 3e [2] 0f 3f [2] 14 39 [2] 08 3e [2] 14 11 }

  condition:
    any of them
}