rule TTP_XOR_QUAD_CurrentVersionRun_317e {
  strings:
    $key_317e = { 62 11 [2] 46 1f [2] 6d 33 [2] 43 11 [2] 57 0a [2] 58 10 [2] 46 0d [2] 44 0c [2] 5f 0a [2] 43 0d [2] 5f 22 }

  condition:
    any of them
}