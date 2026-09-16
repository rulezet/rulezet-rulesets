rule TTP_XOR_QUAD_CurrentVersionRun_7129 {
  strings:
    $key_7129 = { 22 46 [2] 06 48 [2] 2d 64 [2] 03 46 [2] 17 5d [2] 18 47 [2] 06 5a [2] 04 5b [2] 1f 5d [2] 03 5a [2] 1f 75 }

  condition:
    any of them
}