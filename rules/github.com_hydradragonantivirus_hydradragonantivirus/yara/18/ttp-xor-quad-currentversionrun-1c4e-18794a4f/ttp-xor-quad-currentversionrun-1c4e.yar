rule TTP_XOR_QUAD_CurrentVersionRun_1c4e {
  strings:
    $key_1c4e = { 4f 21 [2] 6b 2f [2] 40 03 [2] 6e 21 [2] 7a 3a [2] 75 20 [2] 6b 3d [2] 69 3c [2] 72 3a [2] 6e 3d [2] 72 12 }

  condition:
    any of them
}