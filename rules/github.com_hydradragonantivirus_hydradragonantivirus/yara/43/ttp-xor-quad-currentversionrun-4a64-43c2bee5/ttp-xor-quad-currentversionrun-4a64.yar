rule TTP_XOR_QUAD_CurrentVersionRun_4a64 {
  strings:
    $key_4a64 = { 19 0b [2] 3d 05 [2] 16 29 [2] 38 0b [2] 2c 10 [2] 23 0a [2] 3d 17 [2] 3f 16 [2] 24 10 [2] 38 17 [2] 24 38 }

  condition:
    any of them
}