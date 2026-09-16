rule TTP_XOR_QUAD_CurrentVersionRun_3d5e {
  strings:
    $key_3d5e = { 6e 31 [2] 4a 3f [2] 61 13 [2] 4f 31 [2] 5b 2a [2] 54 30 [2] 4a 2d [2] 48 2c [2] 53 2a [2] 4f 2d [2] 53 02 }

  condition:
    any of them
}