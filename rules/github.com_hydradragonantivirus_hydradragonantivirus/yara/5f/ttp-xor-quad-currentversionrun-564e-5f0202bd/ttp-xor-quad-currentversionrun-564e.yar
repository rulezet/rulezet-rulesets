rule TTP_XOR_QUAD_CurrentVersionRun_564e {
  strings:
    $key_564e = { 05 21 [2] 21 2f [2] 0a 03 [2] 24 21 [2] 30 3a [2] 3f 20 [2] 21 3d [2] 23 3c [2] 38 3a [2] 24 3d [2] 38 12 }

  condition:
    any of them
}