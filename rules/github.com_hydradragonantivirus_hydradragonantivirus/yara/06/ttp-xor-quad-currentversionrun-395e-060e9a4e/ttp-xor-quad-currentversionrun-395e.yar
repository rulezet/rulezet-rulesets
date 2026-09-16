rule TTP_XOR_QUAD_CurrentVersionRun_395e {
  strings:
    $key_395e = { 6a 31 [2] 4e 3f [2] 65 13 [2] 4b 31 [2] 5f 2a [2] 50 30 [2] 4e 2d [2] 4c 2c [2] 57 2a [2] 4b 2d [2] 57 02 }

  condition:
    any of them
}