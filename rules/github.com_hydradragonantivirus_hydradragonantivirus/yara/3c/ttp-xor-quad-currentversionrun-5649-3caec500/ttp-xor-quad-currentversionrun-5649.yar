rule TTP_XOR_QUAD_CurrentVersionRun_5649 {
  strings:
    $key_5649 = { 05 26 [2] 21 28 [2] 0a 04 [2] 24 26 [2] 30 3d [2] 3f 27 [2] 21 3a [2] 23 3b [2] 38 3d [2] 24 3a [2] 38 15 }

  condition:
    any of them
}