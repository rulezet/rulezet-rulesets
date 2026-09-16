rule TTP_XOR_QUAD_CurrentVersionRun_4e0e {
  strings:
    $key_4e0e = { 1d 61 [2] 39 6f [2] 12 43 [2] 3c 61 [2] 28 7a [2] 27 60 [2] 39 7d [2] 3b 7c [2] 20 7a [2] 3c 7d [2] 20 52 }

  condition:
    any of them
}