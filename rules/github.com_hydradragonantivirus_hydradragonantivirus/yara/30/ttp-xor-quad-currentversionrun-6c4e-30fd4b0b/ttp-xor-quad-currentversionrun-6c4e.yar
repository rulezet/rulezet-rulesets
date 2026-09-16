rule TTP_XOR_QUAD_CurrentVersionRun_6c4e {
  strings:
    $key_6c4e = { 3f 21 [2] 1b 2f [2] 30 03 [2] 1e 21 [2] 0a 3a [2] 05 20 [2] 1b 3d [2] 19 3c [2] 02 3a [2] 1e 3d [2] 02 12 }

  condition:
    any of them
}