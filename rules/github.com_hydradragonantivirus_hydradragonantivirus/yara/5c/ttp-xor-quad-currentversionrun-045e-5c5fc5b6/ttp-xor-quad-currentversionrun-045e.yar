rule TTP_XOR_QUAD_CurrentVersionRun_045e {
  strings:
    $key_045e = { 57 31 [2] 73 3f [2] 58 13 [2] 76 31 [2] 62 2a [2] 6d 30 [2] 73 2d [2] 71 2c [2] 6a 2a [2] 76 2d [2] 6a 02 }

  condition:
    any of them
}