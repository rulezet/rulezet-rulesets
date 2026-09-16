rule TTP_XOR_QUAD_CurrentVersionRun_245e {
  strings:
    $key_245e = { 77 31 [2] 53 3f [2] 78 13 [2] 56 31 [2] 42 2a [2] 4d 30 [2] 53 2d [2] 51 2c [2] 4a 2a [2] 56 2d [2] 4a 02 }

  condition:
    any of them
}