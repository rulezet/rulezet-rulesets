rule TTP_XOR_QUAD_CurrentVersionRun_7b0e {
  strings:
    $key_7b0e = { 28 61 [2] 0c 6f [2] 27 43 [2] 09 61 [2] 1d 7a [2] 12 60 [2] 0c 7d [2] 0e 7c [2] 15 7a [2] 09 7d [2] 15 52 }

  condition:
    any of them
}