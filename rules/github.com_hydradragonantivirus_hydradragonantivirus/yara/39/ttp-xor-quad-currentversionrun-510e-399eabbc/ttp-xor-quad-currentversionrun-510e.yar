rule TTP_XOR_QUAD_CurrentVersionRun_510e {
  strings:
    $key_510e = { 02 61 [2] 26 6f [2] 0d 43 [2] 23 61 [2] 37 7a [2] 38 60 [2] 26 7d [2] 24 7c [2] 3f 7a [2] 23 7d [2] 3f 52 }

  condition:
    any of them
}