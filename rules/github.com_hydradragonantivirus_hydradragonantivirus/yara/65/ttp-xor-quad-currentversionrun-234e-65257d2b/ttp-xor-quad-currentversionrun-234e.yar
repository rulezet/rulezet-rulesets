rule TTP_XOR_QUAD_CurrentVersionRun_234e {
  strings:
    $key_234e = { 70 21 [2] 54 2f [2] 7f 03 [2] 51 21 [2] 45 3a [2] 4a 20 [2] 54 3d [2] 56 3c [2] 4d 3a [2] 51 3d [2] 4d 12 }

  condition:
    any of them
}