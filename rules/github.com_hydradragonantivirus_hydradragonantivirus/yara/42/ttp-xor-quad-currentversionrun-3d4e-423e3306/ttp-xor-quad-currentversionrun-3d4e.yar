rule TTP_XOR_QUAD_CurrentVersionRun_3d4e {
  strings:
    $key_3d4e = { 6e 21 [2] 4a 2f [2] 61 03 [2] 4f 21 [2] 5b 3a [2] 54 20 [2] 4a 3d [2] 48 3c [2] 53 3a [2] 4f 3d [2] 53 12 }

  condition:
    any of them
}