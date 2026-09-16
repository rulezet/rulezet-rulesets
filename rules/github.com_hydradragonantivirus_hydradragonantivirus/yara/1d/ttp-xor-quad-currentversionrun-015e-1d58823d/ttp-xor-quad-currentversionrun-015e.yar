rule TTP_XOR_QUAD_CurrentVersionRun_015e {
  strings:
    $key_015e = { 52 31 [2] 76 3f [2] 5d 13 [2] 73 31 [2] 67 2a [2] 68 30 [2] 76 2d [2] 74 2c [2] 6f 2a [2] 73 2d [2] 6f 02 }

  condition:
    any of them
}