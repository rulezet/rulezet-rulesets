rule TTP_XOR_QUAD_CurrentVersionRun_685e {
  strings:
    $key_685e = { 3b 31 [2] 1f 3f [2] 34 13 [2] 1a 31 [2] 0e 2a [2] 01 30 [2] 1f 2d [2] 1d 2c [2] 06 2a [2] 1a 2d [2] 06 02 }

  condition:
    any of them
}