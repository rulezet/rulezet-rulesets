rule TTP_XOR_QUAD_CurrentVersionRun_6e4e {
  strings:
    $key_6e4e = { 3d 21 [2] 19 2f [2] 32 03 [2] 1c 21 [2] 08 3a [2] 07 20 [2] 19 3d [2] 1b 3c [2] 00 3a [2] 1c 3d [2] 00 12 }

  condition:
    any of them
}