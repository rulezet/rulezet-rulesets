rule TTP_XOR_QUAD_CurrentVersionRun_0b5e {
  strings:
    $key_0b5e = { 58 31 [2] 7c 3f [2] 57 13 [2] 79 31 [2] 6d 2a [2] 62 30 [2] 7c 2d [2] 7e 2c [2] 65 2a [2] 79 2d [2] 65 02 }

  condition:
    any of them
}