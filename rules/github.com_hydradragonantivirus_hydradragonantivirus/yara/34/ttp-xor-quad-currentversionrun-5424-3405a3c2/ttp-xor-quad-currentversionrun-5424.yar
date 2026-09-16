rule TTP_XOR_QUAD_CurrentVersionRun_5424 {
  strings:
    $key_5424 = { 07 4b [2] 23 45 [2] 08 69 [2] 26 4b [2] 32 50 [2] 3d 4a [2] 23 57 [2] 21 56 [2] 3a 50 [2] 26 57 [2] 3a 78 }

  condition:
    any of them
}