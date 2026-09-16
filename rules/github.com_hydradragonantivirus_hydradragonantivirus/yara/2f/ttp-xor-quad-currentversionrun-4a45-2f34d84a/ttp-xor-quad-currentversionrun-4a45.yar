rule TTP_XOR_QUAD_CurrentVersionRun_4a45 {
  strings:
    $key_4a45 = { 19 2a [2] 3d 24 [2] 16 08 [2] 38 2a [2] 2c 31 [2] 23 2b [2] 3d 36 [2] 3f 37 [2] 24 31 [2] 38 36 [2] 24 19 }

  condition:
    any of them
}