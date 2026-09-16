rule TTP_XOR_QUAD_CurrentVersionRun_174e {
  strings:
    $key_174e = { 44 21 [2] 60 2f [2] 4b 03 [2] 65 21 [2] 71 3a [2] 7e 20 [2] 60 3d [2] 62 3c [2] 79 3a [2] 65 3d [2] 79 12 }

  condition:
    any of them
}