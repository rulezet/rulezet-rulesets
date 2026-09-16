rule TTP_XOR_QUAD_CurrentVersionRun_4e49 {
  strings:
    $key_4e49 = { 1d 26 [2] 39 28 [2] 12 04 [2] 3c 26 [2] 28 3d [2] 27 27 [2] 39 3a [2] 3b 3b [2] 20 3d [2] 3c 3a [2] 20 15 }

  condition:
    any of them
}