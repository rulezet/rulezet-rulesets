rule TTP_XOR_QUAD_CurrentVersionRun_4f18 {
  strings:
    $key_4f18 = { 1c 77 [2] 38 79 [2] 13 55 [2] 3d 77 [2] 29 6c [2] 26 76 [2] 38 6b [2] 3a 6a [2] 21 6c [2] 3d 6b [2] 21 44 }

  condition:
    any of them
}