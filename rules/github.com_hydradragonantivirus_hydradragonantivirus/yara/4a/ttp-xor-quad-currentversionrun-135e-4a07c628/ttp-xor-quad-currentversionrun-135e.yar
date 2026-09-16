rule TTP_XOR_QUAD_CurrentVersionRun_135e {
  strings:
    $key_135e = { 40 31 [2] 64 3f [2] 4f 13 [2] 61 31 [2] 75 2a [2] 7a 30 [2] 64 2d [2] 66 2c [2] 7d 2a [2] 61 2d [2] 7d 02 }

  condition:
    any of them
}