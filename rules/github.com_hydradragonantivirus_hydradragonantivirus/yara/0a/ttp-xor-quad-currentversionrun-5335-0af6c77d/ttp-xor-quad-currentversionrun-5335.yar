rule TTP_XOR_QUAD_CurrentVersionRun_5335 {
  strings:
    $key_5335 = { 00 5a [2] 24 54 [2] 0f 78 [2] 21 5a [2] 35 41 [2] 3a 5b [2] 24 46 [2] 26 47 [2] 3d 41 [2] 21 46 [2] 3d 69 }

  condition:
    any of them
}