rule TTP_XOR_QUAD_CurrentVersionRun_7c5e {
  strings:
    $key_7c5e = { 2f 31 [2] 0b 3f [2] 20 13 [2] 0e 31 [2] 1a 2a [2] 15 30 [2] 0b 2d [2] 09 2c [2] 12 2a [2] 0e 2d [2] 12 02 }

  condition:
    any of them
}