rule TTP_XOR_QUAD_CurrentVersionRun_f65e {
  strings:
    $key_f65e = { a5 31 [2] 81 3f [2] aa 13 [2] 84 31 [2] 90 2a [2] 9f 30 [2] 81 2d [2] 83 2c [2] 98 2a [2] 84 2d [2] 98 02 }

  condition:
    any of them
}