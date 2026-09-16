rule TTP_XOR_QUAD_CurrentVersionRun_4a38 {
  strings:
    $key_4a38 = { 19 57 [2] 3d 59 [2] 16 75 [2] 38 57 [2] 2c 4c [2] 23 56 [2] 3d 4b [2] 3f 4a [2] 24 4c [2] 38 4b [2] 24 64 }

  condition:
    any of them
}