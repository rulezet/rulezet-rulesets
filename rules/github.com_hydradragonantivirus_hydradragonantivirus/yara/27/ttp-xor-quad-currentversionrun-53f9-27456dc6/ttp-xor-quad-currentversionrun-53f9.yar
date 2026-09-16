rule TTP_XOR_QUAD_CurrentVersionRun_53f9 {
  strings:
    $key_53f9 = { 00 96 [2] 24 98 [2] 0f b4 [2] 21 96 [2] 35 8d [2] 3a 97 [2] 24 8a [2] 26 8b [2] 3d 8d [2] 21 8a [2] 3d a5 }

  condition:
    any of them
}