rule TTP_XOR_QUAD_CurrentVersionRun_5405 {
  strings:
    $key_5405 = { 07 6a [2] 23 64 [2] 08 48 [2] 26 6a [2] 32 71 [2] 3d 6b [2] 23 76 [2] 21 77 [2] 3a 71 [2] 26 76 [2] 3a 59 }

  condition:
    any of them
}