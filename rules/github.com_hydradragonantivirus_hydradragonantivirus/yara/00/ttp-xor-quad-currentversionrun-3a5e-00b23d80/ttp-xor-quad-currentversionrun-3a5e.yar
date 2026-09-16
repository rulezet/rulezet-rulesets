rule TTP_XOR_QUAD_CurrentVersionRun_3a5e {
  strings:
    $key_3a5e = { 69 31 [2] 4d 3f [2] 66 13 [2] 48 31 [2] 5c 2a [2] 53 30 [2] 4d 2d [2] 4f 2c [2] 54 2a [2] 48 2d [2] 54 02 }

  condition:
    any of them
}