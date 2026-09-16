rule TTP_XOR_QUAD_CurrentVersionRun_440e {
  strings:
    $key_440e = { 17 61 [2] 33 6f [2] 18 43 [2] 36 61 [2] 22 7a [2] 2d 60 [2] 33 7d [2] 31 7c [2] 2a 7a [2] 36 7d [2] 2a 52 }

  condition:
    any of them
}