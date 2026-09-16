rule TTP_XOR_QUAD_CurrentVersionRun_3b5e {
  strings:
    $key_3b5e = { 68 31 [2] 4c 3f [2] 67 13 [2] 49 31 [2] 5d 2a [2] 52 30 [2] 4c 2d [2] 4e 2c [2] 55 2a [2] 49 2d [2] 55 02 }

  condition:
    any of them
}