rule TTP_XOR_QUAD_CurrentVersionRun_ea5e {
  strings:
    $key_ea5e = { b9 31 [2] 9d 3f [2] b6 13 [2] 98 31 [2] 8c 2a [2] 83 30 [2] 9d 2d [2] 9f 2c [2] 84 2a [2] 98 2d [2] 84 02 }

  condition:
    any of them
}