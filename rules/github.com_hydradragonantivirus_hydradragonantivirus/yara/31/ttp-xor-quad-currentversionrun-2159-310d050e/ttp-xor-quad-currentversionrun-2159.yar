rule TTP_XOR_QUAD_CurrentVersionRun_2159 {
  strings:
    $key_2159 = { 72 36 [2] 56 38 [2] 7d 14 [2] 53 36 [2] 47 2d [2] 48 37 [2] 56 2a [2] 54 2b [2] 4f 2d [2] 53 2a [2] 4f 05 }

  condition:
    any of them
}