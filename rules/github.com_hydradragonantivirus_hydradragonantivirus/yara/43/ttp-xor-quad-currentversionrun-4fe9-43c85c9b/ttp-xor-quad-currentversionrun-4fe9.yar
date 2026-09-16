rule TTP_XOR_QUAD_CurrentVersionRun_4fe9 {
  strings:
    $key_4fe9 = { 1c 86 [2] 38 88 [2] 13 a4 [2] 3d 86 [2] 29 9d [2] 26 87 [2] 38 9a [2] 3a 9b [2] 21 9d [2] 3d 9a [2] 21 b5 }

  condition:
    any of them
}