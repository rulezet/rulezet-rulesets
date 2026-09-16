rule TTP_XOR_QUAD_CurrentVersionRun_48e4 {
  strings:
    $key_48e4 = { 1b 8b [2] 3f 85 [2] 14 a9 [2] 3a 8b [2] 2e 90 [2] 21 8a [2] 3f 97 [2] 3d 96 [2] 26 90 [2] 3a 97 [2] 26 b8 }

  condition:
    any of them
}