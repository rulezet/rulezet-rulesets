rule TTP_XOR_QUAD_CurrentVersionRun_4ae5 {
  strings:
    $key_4ae5 = { 19 8a [2] 3d 84 [2] 16 a8 [2] 38 8a [2] 2c 91 [2] 23 8b [2] 3d 96 [2] 3f 97 [2] 24 91 [2] 38 96 [2] 24 b9 }

  condition:
    any of them
}