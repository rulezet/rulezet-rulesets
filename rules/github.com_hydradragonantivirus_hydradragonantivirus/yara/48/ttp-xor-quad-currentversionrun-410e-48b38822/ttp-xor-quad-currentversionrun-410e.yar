rule TTP_XOR_QUAD_CurrentVersionRun_410e {
  strings:
    $key_410e = { 12 61 [2] 36 6f [2] 1d 43 [2] 33 61 [2] 27 7a [2] 28 60 [2] 36 7d [2] 34 7c [2] 2f 7a [2] 33 7d [2] 2f 52 }

  condition:
    any of them
}