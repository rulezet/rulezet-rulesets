rule TTP_XOR_QUAD_CurrentVersionRun_655e {
  strings:
    $key_655e = { 36 31 [2] 12 3f [2] 39 13 [2] 17 31 [2] 03 2a [2] 0c 30 [2] 12 2d [2] 10 2c [2] 0b 2a [2] 17 2d [2] 0b 02 }

  condition:
    any of them
}