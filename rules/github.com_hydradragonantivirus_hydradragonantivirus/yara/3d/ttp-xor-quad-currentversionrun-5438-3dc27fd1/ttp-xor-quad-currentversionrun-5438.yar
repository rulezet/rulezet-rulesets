rule TTP_XOR_QUAD_CurrentVersionRun_5438 {
  strings:
    $key_5438 = { 07 57 [2] 23 59 [2] 08 75 [2] 26 57 [2] 32 4c [2] 3d 56 [2] 23 4b [2] 21 4a [2] 3a 4c [2] 26 4b [2] 3a 64 }

  condition:
    any of them
}