rule TTP_XOR_QUAD_CurrentVersionRun_1b4e {
  strings:
    $key_1b4e = { 48 21 [2] 6c 2f [2] 47 03 [2] 69 21 [2] 7d 3a [2] 72 20 [2] 6c 3d [2] 6e 3c [2] 75 3a [2] 69 3d [2] 75 12 }

  condition:
    any of them
}