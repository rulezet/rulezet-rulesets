rule TTP_XOR_QUAD_CurrentVersionRun_647e {
  strings:
    $key_647e = { 37 11 [2] 13 1f [2] 38 33 [2] 16 11 [2] 02 0a [2] 0d 10 [2] 13 0d [2] 11 0c [2] 0a 0a [2] 16 0d [2] 0a 22 }

  condition:
    any of them
}