rule TTP_XOR_QUAD_CurrentVersionRun_4a08 {
  strings:
    $key_4a08 = { 19 67 [2] 3d 69 [2] 16 45 [2] 38 67 [2] 2c 7c [2] 23 66 [2] 3d 7b [2] 3f 7a [2] 24 7c [2] 38 7b [2] 24 54 }

  condition:
    any of them
}