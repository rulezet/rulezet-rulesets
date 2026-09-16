rule TTP_XOR_QUAD_CurrentVersionRun_7a4e {
  strings:
    $key_7a4e = { 29 21 [2] 0d 2f [2] 26 03 [2] 08 21 [2] 1c 3a [2] 13 20 [2] 0d 3d [2] 0f 3c [2] 14 3a [2] 08 3d [2] 14 12 }

  condition:
    any of them
}