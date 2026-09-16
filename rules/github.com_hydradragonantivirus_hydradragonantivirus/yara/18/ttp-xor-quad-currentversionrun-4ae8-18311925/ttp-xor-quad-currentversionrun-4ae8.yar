rule TTP_XOR_QUAD_CurrentVersionRun_4ae8 {
  strings:
    $key_4ae8 = { 19 87 [2] 3d 89 [2] 16 a5 [2] 38 87 [2] 2c 9c [2] 23 86 [2] 3d 9b [2] 3f 9a [2] 24 9c [2] 38 9b [2] 24 b4 }

  condition:
    any of them
}