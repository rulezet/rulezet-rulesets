rule TTP_XOR_QUAD_CurrentVersionRun_1a5e {
  strings:
    $key_1a5e = { 49 31 [2] 6d 3f [2] 46 13 [2] 68 31 [2] 7c 2a [2] 73 30 [2] 6d 2d [2] 6f 2c [2] 74 2a [2] 68 2d [2] 74 02 }

  condition:
    any of them
}