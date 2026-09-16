rule TTP_XOR_QUAD_CurrentVersionRun_2f4e {
  strings:
    $key_2f4e = { 7c 21 [2] 58 2f [2] 73 03 [2] 5d 21 [2] 49 3a [2] 46 20 [2] 58 3d [2] 5a 3c [2] 41 3a [2] 5d 3d [2] 41 12 }

  condition:
    any of them
}