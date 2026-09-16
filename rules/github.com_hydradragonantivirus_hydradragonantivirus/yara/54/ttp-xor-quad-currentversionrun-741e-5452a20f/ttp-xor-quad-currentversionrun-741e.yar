rule TTP_XOR_QUAD_CurrentVersionRun_741e {
  strings:
    $key_741e = { 27 71 [2] 03 7f [2] 28 53 [2] 06 71 [2] 12 6a [2] 1d 70 [2] 03 6d [2] 01 6c [2] 1a 6a [2] 06 6d [2] 1a 42 }

  condition:
    any of them
}