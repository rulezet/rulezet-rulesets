rule TTP_XOR_QUAD_CurrentVersionRun_7859 {
  strings:
    $key_7859 = { 2b 36 [2] 0f 38 [2] 24 14 [2] 0a 36 [2] 1e 2d [2] 11 37 [2] 0f 2a [2] 0d 2b [2] 16 2d [2] 0a 2a [2] 16 05 }

  condition:
    any of them
}