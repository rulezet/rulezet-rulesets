rule TTP_XOR_QUAD_CurrentVersionRun_f15e {
  strings:
    $key_f15e = { a2 31 [2] 86 3f [2] ad 13 [2] 83 31 [2] 97 2a [2] 98 30 [2] 86 2d [2] 84 2c [2] 9f 2a [2] 83 2d [2] 9f 02 }

  condition:
    any of them
}