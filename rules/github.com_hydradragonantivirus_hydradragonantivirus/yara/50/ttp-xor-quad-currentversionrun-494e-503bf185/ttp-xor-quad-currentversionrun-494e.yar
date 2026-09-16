rule TTP_XOR_QUAD_CurrentVersionRun_494e {
  strings:
    $key_494e = { 1a 21 [2] 3e 2f [2] 15 03 [2] 3b 21 [2] 2f 3a [2] 20 20 [2] 3e 3d [2] 3c 3c [2] 27 3a [2] 3b 3d [2] 27 12 }

  condition:
    any of them
}