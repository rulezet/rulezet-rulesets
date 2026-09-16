rule TTP_XOR_QUAD_CurrentVersionRun_e85e {
  strings:
    $key_e85e = { bb 31 [2] 9f 3f [2] b4 13 [2] 9a 31 [2] 8e 2a [2] 81 30 [2] 9f 2d [2] 9d 2c [2] 86 2a [2] 9a 2d [2] 86 02 }

  condition:
    any of them
}