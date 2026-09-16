rule TTP_XOR_QUAD_CurrentVersionRun_443e {
  strings:
    $key_443e = { 17 51 [2] 33 5f [2] 18 73 [2] 36 51 [2] 22 4a [2] 2d 50 [2] 33 4d [2] 31 4c [2] 2a 4a [2] 36 4d [2] 2a 62 }

  condition:
    any of them
}