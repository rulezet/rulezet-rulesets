rule TTP_XOR_QUAD_CurrentVersionRun_567e {
  strings:
    $key_567e = { 05 11 [2] 21 1f [2] 0a 33 [2] 24 11 [2] 30 0a [2] 3f 10 [2] 21 0d [2] 23 0c [2] 38 0a [2] 24 0d [2] 38 22 }

  condition:
    any of them
}