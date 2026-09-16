rule TTP_XOR_QUAD_CurrentVersionRun_ef5e {
  strings:
    $key_ef5e = { bc 31 [2] 98 3f [2] b3 13 [2] 9d 31 [2] 89 2a [2] 86 30 [2] 98 2d [2] 9a 2c [2] 81 2a [2] 9d 2d [2] 81 02 }

  condition:
    any of them
}