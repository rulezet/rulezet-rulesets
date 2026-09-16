rule TTP_XOR_QUAD_CurrentVersionRun_7f4c {
  strings:
    $key_7f4c = { 2c 23 [2] 08 2d [2] 23 01 [2] 0d 23 [2] 19 38 [2] 16 22 [2] 08 3f [2] 0a 3e [2] 11 38 [2] 0d 3f [2] 11 10 }

  condition:
    any of them
}