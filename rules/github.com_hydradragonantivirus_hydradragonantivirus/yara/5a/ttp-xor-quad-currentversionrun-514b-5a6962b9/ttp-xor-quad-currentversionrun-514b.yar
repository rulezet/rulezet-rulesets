rule TTP_XOR_QUAD_CurrentVersionRun_514b {
  strings:
    $key_514b = { 02 24 [2] 26 2a [2] 0d 06 [2] 23 24 [2] 37 3f [2] 38 25 [2] 26 38 [2] 24 39 [2] 3f 3f [2] 23 38 [2] 3f 17 }

  condition:
    any of them
}