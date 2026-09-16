rule TTP_XOR_QUAD_CurrentVersionRun_4f05 {
  strings:
    $key_4f05 = { 1c 6a [2] 38 64 [2] 13 48 [2] 3d 6a [2] 29 71 [2] 26 6b [2] 38 76 [2] 3a 77 [2] 21 71 [2] 3d 76 [2] 21 59 }

  condition:
    any of them
}