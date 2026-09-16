rule TTP_XOR_QUAD_CurrentVersionRun_0b4e {
  strings:
    $key_0b4e = { 58 21 [2] 7c 2f [2] 57 03 [2] 79 21 [2] 6d 3a [2] 62 20 [2] 7c 3d [2] 7e 3c [2] 65 3a [2] 79 3d [2] 65 12 }

  condition:
    any of them
}