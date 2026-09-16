rule TTP_XOR_QUAD_CurrentVersionRun_513e {
  strings:
    $key_513e = { 02 51 [2] 26 5f [2] 0d 73 [2] 23 51 [2] 37 4a [2] 38 50 [2] 26 4d [2] 24 4c [2] 3f 4a [2] 23 4d [2] 3f 62 }

  condition:
    any of them
}