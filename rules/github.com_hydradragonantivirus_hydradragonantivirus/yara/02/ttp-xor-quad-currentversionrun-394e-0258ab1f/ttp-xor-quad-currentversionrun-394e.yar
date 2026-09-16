rule TTP_XOR_QUAD_CurrentVersionRun_394e {
  strings:
    $key_394e = { 6a 21 [2] 4e 2f [2] 65 03 [2] 4b 21 [2] 5f 3a [2] 50 20 [2] 4e 3d [2] 4c 3c [2] 57 3a [2] 4b 3d [2] 57 12 }

  condition:
    any of them
}