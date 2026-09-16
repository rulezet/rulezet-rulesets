rule TTP_XOR_QUAD_CurrentVersionRun_4f0e {
  strings:
    $key_4f0e = { 1c 61 [2] 38 6f [2] 13 43 [2] 3d 61 [2] 29 7a [2] 26 60 [2] 38 7d [2] 3a 7c [2] 21 7a [2] 3d 7d [2] 21 52 }

  condition:
    any of them
}