rule TTP_XOR_QUAD_CurrentVersionRun_4a18 {
  strings:
    $key_4a18 = { 19 77 [2] 3d 79 [2] 16 55 [2] 38 77 [2] 2c 6c [2] 23 76 [2] 3d 6b [2] 3f 6a [2] 24 6c [2] 38 6b [2] 24 44 }

  condition:
    any of them
}