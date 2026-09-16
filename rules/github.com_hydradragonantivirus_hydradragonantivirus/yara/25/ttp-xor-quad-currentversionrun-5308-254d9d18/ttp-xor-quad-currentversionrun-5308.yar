rule TTP_XOR_QUAD_CurrentVersionRun_5308 {
  strings:
    $key_5308 = { 00 67 [2] 24 69 [2] 0f 45 [2] 21 67 [2] 35 7c [2] 3a 66 [2] 24 7b [2] 26 7a [2] 3d 7c [2] 21 7b [2] 3d 54 }

  condition:
    any of them
}