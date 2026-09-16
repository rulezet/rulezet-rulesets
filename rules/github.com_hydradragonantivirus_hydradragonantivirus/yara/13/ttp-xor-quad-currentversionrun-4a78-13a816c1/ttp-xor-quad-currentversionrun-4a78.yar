rule TTP_XOR_QUAD_CurrentVersionRun_4a78 {
  strings:
    $key_4a78 = { 19 17 [2] 3d 19 [2] 16 35 [2] 38 17 [2] 2c 0c [2] 23 16 [2] 3d 0b [2] 3f 0a [2] 24 0c [2] 38 0b [2] 24 24 }

  condition:
    any of them
}