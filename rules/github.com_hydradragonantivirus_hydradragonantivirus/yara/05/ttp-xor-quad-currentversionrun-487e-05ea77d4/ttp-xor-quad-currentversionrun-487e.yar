rule TTP_XOR_QUAD_CurrentVersionRun_487e {
  strings:
    $key_487e = { 1b 11 [2] 3f 1f [2] 14 33 [2] 3a 11 [2] 2e 0a [2] 21 10 [2] 3f 0d [2] 3d 0c [2] 26 0a [2] 3a 0d [2] 26 22 }

  condition:
    any of them
}