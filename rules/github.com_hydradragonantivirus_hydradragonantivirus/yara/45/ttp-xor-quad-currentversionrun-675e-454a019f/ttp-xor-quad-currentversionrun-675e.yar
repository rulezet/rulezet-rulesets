rule TTP_XOR_QUAD_CurrentVersionRun_675e {
  strings:
    $key_675e = { 34 31 [2] 10 3f [2] 3b 13 [2] 15 31 [2] 01 2a [2] 0e 30 [2] 10 2d [2] 12 2c [2] 09 2a [2] 15 2d [2] 09 02 }

  condition:
    any of them
}