rule TTP_XOR_QUAD_CurrentVersionRun_7649 {
  strings:
    $key_7649 = { 25 26 [2] 01 28 [2] 2a 04 [2] 04 26 [2] 10 3d [2] 1f 27 [2] 01 3a [2] 03 3b [2] 18 3d [2] 04 3a [2] 18 15 }

  condition:
    any of them
}