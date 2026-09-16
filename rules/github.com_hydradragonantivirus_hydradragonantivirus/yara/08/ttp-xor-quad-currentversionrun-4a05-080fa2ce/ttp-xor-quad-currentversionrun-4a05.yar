rule TTP_XOR_QUAD_CurrentVersionRun_4a05 {
  strings:
    $key_4a05 = { 19 6a [2] 3d 64 [2] 16 48 [2] 38 6a [2] 2c 71 [2] 23 6b [2] 3d 76 [2] 3f 77 [2] 24 71 [2] 38 76 [2] 24 59 }

  condition:
    any of them
}