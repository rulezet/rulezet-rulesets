rule TTP_XOR_QUAD_CurrentVersionRun_4a19 {
  strings:
    $key_4a19 = { 19 76 [2] 3d 78 [2] 16 54 [2] 38 76 [2] 2c 6d [2] 23 77 [2] 3d 6a [2] 3f 6b [2] 24 6d [2] 38 6a [2] 24 45 }

  condition:
    any of them
}