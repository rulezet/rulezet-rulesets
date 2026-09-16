rule TTP_XOR_QUAD_CurrentVersionRun_6f0e {
  strings:
    $key_6f0e = { 3c 61 [2] 18 6f [2] 33 43 [2] 1d 61 [2] 09 7a [2] 06 60 [2] 18 7d [2] 1a 7c [2] 01 7a [2] 1d 7d [2] 01 52 }

  condition:
    any of them
}