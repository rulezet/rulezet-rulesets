rule TTP_XOR_QUAD_CurrentVersionRun_4af9 {
  strings:
    $key_4af9 = { 19 96 [2] 3d 98 [2] 16 b4 [2] 38 96 [2] 2c 8d [2] 23 97 [2] 3d 8a [2] 3f 8b [2] 24 8d [2] 38 8a [2] 24 a5 }

  condition:
    any of them
}