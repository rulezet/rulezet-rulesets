rule TTP_XOR_QUAD_CurrentVersionRun_0c5e {
  strings:
    $key_0c5e = { 5f 31 [2] 7b 3f [2] 50 13 [2] 7e 31 [2] 6a 2a [2] 65 30 [2] 7b 2d [2] 79 2c [2] 62 2a [2] 7e 2d [2] 62 02 }

  condition:
    any of them
}