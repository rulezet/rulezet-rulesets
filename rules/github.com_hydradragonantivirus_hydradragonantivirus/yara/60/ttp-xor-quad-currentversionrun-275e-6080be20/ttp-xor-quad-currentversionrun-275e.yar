rule TTP_XOR_QUAD_CurrentVersionRun_275e {
  strings:
    $key_275e = { 74 31 [2] 50 3f [2] 7b 13 [2] 55 31 [2] 41 2a [2] 4e 30 [2] 50 2d [2] 52 2c [2] 49 2a [2] 55 2d [2] 49 02 }

  condition:
    any of them
}