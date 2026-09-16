rule TTP_XOR_QUAD_CurrentVersionRun_125e {
  strings:
    $key_125e = { 41 31 [2] 65 3f [2] 4e 13 [2] 60 31 [2] 74 2a [2] 7b 30 [2] 65 2d [2] 67 2c [2] 7c 2a [2] 60 2d [2] 7c 02 }

  condition:
    any of them
}