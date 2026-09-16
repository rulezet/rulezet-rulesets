rule TTP_XOR_QUAD_CurrentVersionRun_413e {
  strings:
    $key_413e = { 12 51 [2] 36 5f [2] 1d 73 [2] 33 51 [2] 27 4a [2] 28 50 [2] 36 4d [2] 34 4c [2] 2f 4a [2] 33 4d [2] 2f 62 }

  condition:
    any of them
}