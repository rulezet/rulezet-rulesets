rule TTP_XOR_QUAD_CurrentVersionRun_254e {
  strings:
    $key_254e = { 76 21 [2] 52 2f [2] 79 03 [2] 57 21 [2] 43 3a [2] 4c 20 [2] 52 3d [2] 50 3c [2] 4b 3a [2] 57 3d [2] 4b 12 }

  condition:
    any of them
}