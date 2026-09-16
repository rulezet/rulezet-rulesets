rule TTP_XOR_QUAD_CurrentVersionRun_4af4 {
  strings:
    $key_4af4 = { 19 9b [2] 3d 95 [2] 16 b9 [2] 38 9b [2] 2c 80 [2] 23 9a [2] 3d 87 [2] 3f 86 [2] 24 80 [2] 38 87 [2] 24 a8 }

  condition:
    any of them
}