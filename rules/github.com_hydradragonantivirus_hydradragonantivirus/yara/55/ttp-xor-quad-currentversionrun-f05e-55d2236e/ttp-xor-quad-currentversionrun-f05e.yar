rule TTP_XOR_QUAD_CurrentVersionRun_f05e {
  strings:
    $key_f05e = { a3 31 [2] 87 3f [2] ac 13 [2] 82 31 [2] 96 2a [2] 99 30 [2] 87 2d [2] 85 2c [2] 9e 2a [2] 82 2d [2] 9e 02 }

  condition:
    any of them
}