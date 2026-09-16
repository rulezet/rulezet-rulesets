rule TTP_XOR_QUAD_CurrentVersionRun_412e {
  strings:
    $key_412e = { 12 41 [2] 36 4f [2] 1d 63 [2] 33 41 [2] 27 5a [2] 28 40 [2] 36 5d [2] 34 5c [2] 2f 5a [2] 33 5d [2] 2f 72 }

  condition:
    any of them
}