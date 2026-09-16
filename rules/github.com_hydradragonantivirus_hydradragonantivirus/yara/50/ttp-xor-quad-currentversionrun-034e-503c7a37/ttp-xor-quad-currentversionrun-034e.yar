rule TTP_XOR_QUAD_CurrentVersionRun_034e {
  strings:
    $key_034e = { 50 21 [2] 74 2f [2] 5f 03 [2] 71 21 [2] 65 3a [2] 6a 20 [2] 74 3d [2] 76 3c [2] 6d 3a [2] 71 3d [2] 6d 12 }

  condition:
    any of them
}