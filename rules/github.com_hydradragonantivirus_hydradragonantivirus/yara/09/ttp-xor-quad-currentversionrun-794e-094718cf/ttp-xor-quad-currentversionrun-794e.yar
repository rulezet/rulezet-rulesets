rule TTP_XOR_QUAD_CurrentVersionRun_794e {
  strings:
    $key_794e = { 2a 21 [2] 0e 2f [2] 25 03 [2] 0b 21 [2] 1f 3a [2] 10 20 [2] 0e 3d [2] 0c 3c [2] 17 3a [2] 0b 3d [2] 17 12 }

  condition:
    any of them
}