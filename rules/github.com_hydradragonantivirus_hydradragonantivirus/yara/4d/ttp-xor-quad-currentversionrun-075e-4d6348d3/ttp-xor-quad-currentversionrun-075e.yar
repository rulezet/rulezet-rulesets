rule TTP_XOR_QUAD_CurrentVersionRun_075e {
  strings:
    $key_075e = { 54 31 [2] 70 3f [2] 5b 13 [2] 75 31 [2] 61 2a [2] 6e 30 [2] 70 2d [2] 72 2c [2] 69 2a [2] 75 2d [2] 69 02 }

  condition:
    any of them
}