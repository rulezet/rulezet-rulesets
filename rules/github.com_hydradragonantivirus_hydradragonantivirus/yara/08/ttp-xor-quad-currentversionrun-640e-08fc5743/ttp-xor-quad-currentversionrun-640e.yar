rule TTP_XOR_QUAD_CurrentVersionRun_640e {
  strings:
    $key_640e = { 37 61 [2] 13 6f [2] 38 43 [2] 16 61 [2] 02 7a [2] 0d 60 [2] 13 7d [2] 11 7c [2] 0a 7a [2] 16 7d [2] 0a 52 }

  condition:
    any of them
}