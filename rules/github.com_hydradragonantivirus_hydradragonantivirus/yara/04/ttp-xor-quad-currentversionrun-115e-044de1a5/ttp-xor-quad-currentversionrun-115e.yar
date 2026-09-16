rule TTP_XOR_QUAD_CurrentVersionRun_115e {
  strings:
    $key_115e = { 42 31 [2] 66 3f [2] 4d 13 [2] 63 31 [2] 77 2a [2] 78 30 [2] 66 2d [2] 64 2c [2] 7f 2a [2] 63 2d [2] 7f 02 }

  condition:
    any of them
}