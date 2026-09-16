rule TTP_XOR_QUAD_CurrentVersionRun_035e {
  strings:
    $key_035e = { 50 31 [2] 74 3f [2] 5f 13 [2] 71 31 [2] 65 2a [2] 6a 30 [2] 74 2d [2] 76 2c [2] 6d 2a [2] 71 2d [2] 6d 02 }

  condition:
    any of them
}