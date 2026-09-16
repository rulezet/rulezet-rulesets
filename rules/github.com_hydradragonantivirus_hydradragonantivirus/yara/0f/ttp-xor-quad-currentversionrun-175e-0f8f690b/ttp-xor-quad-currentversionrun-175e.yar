rule TTP_XOR_QUAD_CurrentVersionRun_175e {
  strings:
    $key_175e = { 44 31 [2] 60 3f [2] 4b 13 [2] 65 31 [2] 71 2a [2] 7e 30 [2] 60 2d [2] 62 2c [2] 79 2a [2] 65 2d [2] 79 02 }

  condition:
    any of them
}